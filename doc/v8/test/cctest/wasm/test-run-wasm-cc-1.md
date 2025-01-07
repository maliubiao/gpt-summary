Response:
The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of a larger file. I need to:

1. **Identify the main purpose:** The code consists of several test cases for WebAssembly (Wasm) functionality in the V8 JavaScript engine.
2. **Analyze each test case:** Determine what aspect of Wasm each test is verifying. Look for patterns in the `WASM_EXEC_TEST` macros and the `WasmRunner` usage.
3. **Categorize the tests:** Group similar tests together for a more concise summary.
4. **Address specific instructions:**
    - `.tq` extension:  The code does *not* end in `.tq`, so it's not Torque code.
    - JavaScript relation:  These tests are part of V8, the engine that runs JavaScript. I'll provide an example of how the tested Wasm features could be used from JavaScript.
    - Code logic inference: Some tests involve conditional logic. I'll provide an example with input and expected output.
    - Common programming errors:  Some tests check for memory access errors. I'll illustrate a common mistake that leads to such errors.
5. **Summarize the overall functionality:** Provide a high-level description of the code's role within V8.
这是V8源代码文件 `v8/test/cctest/wasm/test-run-wasm.cc` 的一部分，它包含了一系列用于测试 WebAssembly (Wasm) 功能的 C++ 测试用例。这些测试用例使用 `WasmRunner` 类来构建和执行 Wasm 模块，并使用 `CHECK_EQ` 等宏来验证执行结果是否符合预期。

**功能归纳:**

这部分代码主要测试了以下 Wasm 指令和概念：

1. **`select` 指令:**
   - 测试了 `select` 指令在不同数据类型 (i32, i64) 和有无显式类型声明的情况下的行为。
   - 验证了 `select` 指令在条件为真或假时返回正确的操作数。
   - 测试了包含副作用的 `select` 指令的执行顺序 (`strict1` 测试用例)。

2. **控制流指令:**
   - **`br_if` 指令:** 测试了带条件的跳转指令，验证了当条件满足时跳转，否则继续执行。
   - **`br` 指令:**  测试了无条件跳转指令，验证了跳转到指定代码块的能力。
   - **`br_table` 指令:** 重点测试了跳转表指令，包括：
     - 没有 case 的跳转表 (`BrTable0a`, `BrTable0b`).
     - 有多个 case 的跳转表 (`BrTable0c`).
     - 跳转到不同嵌套层级的代码块 (`BrTable1`).
     - 在循环中使用跳转表 (`BrTable_loop`).
     - 跳转到其他 `br` 指令的目标 (`BrTable_br`, `BrTable_br2`).
     - 复杂的跳转表场景，包含多个 case 和不同的跳转目标 (`BrTable4`, `BrTable4x4`).
     - 跳转表 fall-through 的行为 (`BrTable4_fallthru`).
     - 跳转表跳转到循环的开始 (`BrTable_loop_target`).

3. **内存操作指令:**
   - **`i32.reinterpret_f32` 和 `f32.reinterpret_i32`:** 测试了不同数据类型之间的按位重新解释，验证了浮点数和整数之间的转换。
   - **`load` 指令:**
     - 测试了加载不同大小和对齐方式的数据 (`LoadMemI32`, `UnalignedFloat32Load`, `UnalignedFloat64Load`, `UnalignedInt32Load`).
     - 测试了加载操作的越界访问行为 (`LoadMaxUint32Offset`, `LoadMemI32_oob`, `LoadMem_offset_oob`).
     - 测试了带偏移量的加载操作 (`LoadMemI32_offset`).
     - 测试了常量索引的加载操作 (`LoadMemI32_const_oob_misaligned`, `LoadMemI32_const_oob`).
   - **`store` 指令:**
     - 测试了存储不同大小和对齐方式的数据 (`UnalignedInt32Store`, `UnalignedFloat32Store`, `UnalignedFloat64Store`, `StoreMemI32_alignment`).
     - 测试了带偏移量的存储操作 (`StoreMemI32_offset`).
     - 测试了存储操作的越界访问行为 (`StoreMem_offset_oob`).
     - 测试了窄化存储操作 (`Store_i32_narrowed`)，例如将 i32 值存储到 i8 或 i16 类型的内存位置。

4. **函数调用:**
   - 测试了无返回值函数的调用 (`VoidReturn1`, `VoidReturn2`).

5. **代码块 (`block`) 和循环 (`loop`) 指令:**
   - 测试了空代码块和循环 (`Block_empty`, `Loop_empty`).
   - 测试了带有返回值和不同数据类型的代码块和循环 (`Block_i`, `Block_f`, `Block_d`, `Loop_i`, `Loop_f`, `Loop_d`).
   - 测试了在代码块和循环中使用 `br` 和 `br_if` 指令跳出 (`Block_empty_br1`, `Block_empty_brif1`, `Block_empty_brif2`, `Loop_empty_br1`, `Loop_empty_brif1`, `Loop_empty_brif2`, `Loop_empty_brif3`).

6. **条件语句 (`if`, `if-else`):**
   - 测试了 `if` 语句在不同场景下的行为，包括赋值和跳转 (`Block_If_P`, `Block_If_P_assign`, `IfBreak1`, `IfBreak2`).
   - 测试了 `if-else` 语句，包括赋值和返回 (`Block_IfElse_P_assign`, `Block_IfElse_P_return`).
   - 测试了表达式形式的 `if-else` (`ExprIf_P`).

7. **其他指令和概念:**
   - **`local.get` 和 `local.set`:** 隐式地在许多测试用例中使用，用于访问和修改局部变量。
   - **`local.tee`:** 测试了 `local.tee` 指令，它在设置局部变量的同时返回该值 (`DanglingAssign`).
   - **`return`:** 用于从函数中返回值。
   - **`unreachable`:** 用于指示代码不应该被执行到 (`IfBreak1`).
   - **`nop`:** 空操作指令 (`VoidReturn1`).
   - **`drop`:** 丢弃栈顶的值 (`Loop_if_break2`).
   - **`while` 循环:** 使用 `loop` 和 `br_if` 模拟 `while` 循环 (`CountDown`, `WhileCountDown`).
   - **常量 (`i32.const` 等):** 用于提供测试的输入值。

**关于其他问题的解答:**

* **`.tq` 结尾:**  `v8/test/cctest/wasm/test-run-wasm.cc` 的文件名以 `.cc` 结尾，因此它是一个 C++ 源代码文件，而不是 Torque 文件。

* **与 JavaScript 的功能关系:**  这些测试验证了 WebAssembly 的功能，而 WebAssembly 可以在 JavaScript 环境中运行。以下是一个简单的 JavaScript 示例，展示了如何加载和使用一个包含 `select` 指令的 Wasm 模块：

```javascript
async function runWasm() {
  const response = await fetch('module.wasm'); // 假设有一个名为 module.wasm 的 Wasm 文件
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  // 假设 Wasm 模块导出一个名为 'selectExample' 的函数，它接受一个整数参数
  const result1 = instance.exports.selectExample(1); // 传入 1，条件为真
  console.log(result1); // 预期输出取决于 Wasm 模块中的 select 指令

  const result0 = instance.exports.selectExample(0); // 传入 0，条件为假
  console.log(result0); // 预期输出取决于 Wasm 模块中的 select 指令
}

runWasm();
```

* **代码逻辑推理:** 以 `WASM_EXEC_TEST(Select32)` 为例：

   **假设输入:**
   - 执行 `r.Call(1)`，即传入整数 `1`。
   - 执行 `r.Call(0)`，即传入整数 `0`。

   **代码逻辑:**
   `r.Build({WASM_SELECT(WASM_I32V_1(11), WASM_I32V_1(22), WASM_LOCAL_GET(0))});`
   这部分 Wasm 代码相当于 `condition ? 11 : 22`，其中 `condition` 的值由传入的参数决定。

   **预期输出:**
   - 当输入为 `1` 时 (条件为真)，`select` 指令返回 `11`。
   - 当输入为 `0` 时 (条件为假)，`select` 指令返回 `22`。

* **涉及用户常见的编程错误:**  许多内存相关的测试（例如，带有 `_oob` 后缀的测试）旨在检测因错误的内存访问而导致的陷阱 (trap)。一个常见的编程错误是**数组越界访问**，在 Wasm 中这会导致运行时错误。

   **JavaScript 示例（与 Wasm 内存访问类似的概念）：**

   ```javascript
   const myArray = [10, 20, 30];
   const index = 5; // 这是一个超出数组边界的索引

   // 尝试访问超出数组边界的元素会导致错误
   console.log(myArray[index]); // 输出 undefined 或引发错误，具体取决于环境
   ```

   在 Wasm 中，尝试加载或存储到超出已分配内存范围的地址会导致 trap。测试用例 `LoadMemI32_oob` 就是为了验证这种行为。

总而言之，这部分 `test-run-wasm.cc` 文件专注于对 V8 引擎中核心 Wasm 指令的行为进行细致的单元测试，涵盖了数据操作、控制流、内存访问和函数调用等关键方面，确保了 V8 正确地执行各种 Wasm 代码。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
WASM_I64V_1(22), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int64_t expected = i ? 11 : 22;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Select64WithType) {
  WasmRunner<int64_t, int32_t> r(execution_tier);
  // return select(11, 22, a);
  r.Build({WASM_SELECT_L(WASM_I64V_1(11), WASM_I64V_1(22), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int64_t expected = i ? 11 : 22;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Select64_strict1) {
  WasmRunner<int64_t, int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI64);
  r.AllocateLocal(kWasmI64);
  // select(b=5, c=6, a)
  r.Build({WASM_SELECT(WASM_LOCAL_TEE(1, WASM_I64V_1(5)),
                       WASM_LOCAL_TEE(2, WASM_I64V_1(6)), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int64_t expected = i ? 5 : 6;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Select64WithType_strict1) {
  WasmRunner<int64_t, int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI64);
  r.AllocateLocal(kWasmI64);
  // select(b=5, c=6, a)
  r.Build(
      {WASM_SELECT_L(WASM_LOCAL_TEE(1, WASM_I64V_1(5)),
                     WASM_LOCAL_TEE(2, WASM_I64V_1(6)), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int64_t expected = i ? 5 : 6;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(BrIf_strict) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(
      WASM_BRV_IF(0, WASM_LOCAL_GET(0), WASM_LOCAL_TEE(0, WASM_I32V_2(99))))});

  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Br_height) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(
      WASM_BLOCK(WASM_BRV_IFD(0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(0)),
                 WASM_RETURN(WASM_I32V_1(9))),
      WASM_BRV(0, WASM_I32V_1(8)))});

  for (int32_t i = 0; i < 5; i++) {
    int32_t expected = i != 0 ? 8 : 9;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Regression_660262) {
  WasmRunner<int32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({kExprI32Const, 0x00, kExprI32Const, 0x00, kExprI32LoadMem, 0x00,
           0x0F, kExprBrTable, 0x00, 0x80, 0x00});  // entries=0
  r.Call();
}

WASM_EXEC_TEST(BrTable0a) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 0, BR_TARGET(0)))),
           WASM_I32V_2(91)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(91, r.Call(i)); }
}

WASM_EXEC_TEST(BrTable0b) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build(
      {B1(B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 1, BR_TARGET(0), BR_TARGET(0)))),
       WASM_I32V_2(92)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(92, r.Call(i)); }
}

WASM_EXEC_TEST(BrTable0c) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(B2(B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 1, BR_TARGET(0),
                                  BR_TARGET(1))),
                 RET_I8(76))),
           WASM_I32V_2(77)});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i == 0 ? 76 : 77;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(BrTable1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 0, BR_TARGET(0))), RET_I8(93)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(93, r.Call(i)); }
}

WASM_EXEC_TEST(BrTable_loop) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build(
      {B2(B1(WASM_LOOP(WASM_BR_TABLE(WASM_INC_LOCAL_BYV(0, 1), 2, BR_TARGET(2),
                                     BR_TARGET(1), BR_TARGET(0)))),
          RET_I8(99)),
       WASM_I32V_2(98)});
  CHECK_EQ(99, r.Call(0));
  CHECK_EQ(98, r.Call(-1));
  CHECK_EQ(98, r.Call(-2));
  CHECK_EQ(98, r.Call(-3));
  CHECK_EQ(98, r.Call(-100));
}

WASM_EXEC_TEST(BrTable_br) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build(
      {B2(B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 1, BR_TARGET(1), BR_TARGET(0))),
          RET_I8(91)),
       WASM_I32V_2(99)});
  CHECK_EQ(99, r.Call(0));
  CHECK_EQ(91, r.Call(1));
  CHECK_EQ(91, r.Call(2));
  CHECK_EQ(91, r.Call(3));
}

WASM_EXEC_TEST(BrTable_br2) {
  WasmRunner<int32_t, int32_t> r(execution_tier);

  r.Build({B2(B2(B2(B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 3, BR_TARGET(1),
                                     BR_TARGET(2), BR_TARGET(3), BR_TARGET(0))),
                    RET_I8(85)),
                 RET_I8(86)),
              RET_I8(87)),
           WASM_I32V_2(88)});
  CHECK_EQ(86, r.Call(0));
  CHECK_EQ(87, r.Call(1));
  CHECK_EQ(88, r.Call(2));
  CHECK_EQ(85, r.Call(3));
  CHECK_EQ(85, r.Call(4));
  CHECK_EQ(85, r.Call(5));
}

WASM_EXEC_TEST(BrTable4) {
  for (int i = 0; i < 4; ++i) {
    for (int t = 0; t < 4; ++t) {
      uint32_t cases[] = {0, 1, 2, 3};
      cases[i] = t;

      WasmRunner<int32_t, int32_t> r(execution_tier);
      r.Build({B2(B2(B2(B2(B1(WASM_BR_TABLE(
                               WASM_LOCAL_GET(0), 3, BR_TARGET(cases[0]),
                               BR_TARGET(cases[1]), BR_TARGET(cases[2]),
                               BR_TARGET(cases[3]))),
                           RET_I8(70)),
                        RET_I8(71)),
                     RET_I8(72)),
                  RET_I8(73)),
               WASM_I32V_2(75)});

      for (int x = -3; x < 50; ++x) {
        int index = (x > 3 || x < 0) ? 3 : x;
        int32_t expected = 70 + cases[index];
        CHECK_EQ(expected, r.Call(x));
      }
    }
  }
}

WASM_EXEC_TEST(BrTable4x4) {
  for (uint8_t a = 0; a < 4; ++a) {
    for (uint8_t b = 0; b < 4; ++b) {
      for (uint8_t c = 0; c < 4; ++c) {
        for (uint8_t d = 0; d < 4; ++d) {
          for (int i = 0; i < 4; ++i) {
            uint32_t cases[] = {a, b, c, d};

            WasmRunner<int32_t, int32_t> r(execution_tier);
            r.Build({B2(B2(B2(B2(B1(WASM_BR_TABLE(
                                     WASM_LOCAL_GET(0), 3, BR_TARGET(cases[0]),
                                     BR_TARGET(cases[1]), BR_TARGET(cases[2]),
                                     BR_TARGET(cases[3]))),
                                 RET_I8(50)),
                              RET_I8(51)),
                           RET_I8(52)),
                        RET_I8(53)),
                     WASM_I32V_2(55)});

            for (int x = -6; x < 47; ++x) {
              int index = (x > 3 || x < 0) ? 3 : x;
              int32_t expected = 50 + cases[index];
              CHECK_EQ(expected, r.Call(x));
            }
          }
        }
      }
    }
  }
}

WASM_EXEC_TEST(BrTable4_fallthru) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build(
      {B2(B2(B2(B2(B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 3, BR_TARGET(0),
                                    BR_TARGET(1), BR_TARGET(2), BR_TARGET(3))),
                   WASM_INC_LOCAL_BY(1, 1)),
                WASM_INC_LOCAL_BY(1, 2)),
             WASM_INC_LOCAL_BY(1, 4)),
          WASM_INC_LOCAL_BY(1, 8)),
       WASM_LOCAL_GET(1)});

  CHECK_EQ(15, r.Call(0, 0));
  CHECK_EQ(14, r.Call(1, 0));
  CHECK_EQ(12, r.Call(2, 0));
  CHECK_EQ(8, r.Call(3, 0));
  CHECK_EQ(8, r.Call(4, 0));

  CHECK_EQ(115, r.Call(0, 100));
  CHECK_EQ(114, r.Call(1, 100));
  CHECK_EQ(112, r.Call(2, 100));
  CHECK_EQ(108, r.Call(3, 100));
  CHECK_EQ(108, r.Call(4, 100));
}

WASM_EXEC_TEST(BrTable_loop_target) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build(
      {WASM_LOOP_I(WASM_BLOCK(WASM_BR_TABLE(WASM_LOCAL_GET(0), 2, BR_TARGET(0),
                                            BR_TARGET(1), BR_TARGET(1))),
                   WASM_ONE)});

  CHECK_EQ(1, r.Call(0));
}

WASM_EXEC_TEST(I32ReinterpretF32) {
  WasmRunner<int32_t> r(execution_tier);
  float* memory =
      r.builder().AddMemoryElems<float>(kWasmPageSize / sizeof(float));

  r.Build({WASM_I32_REINTERPRET_F32(
      WASM_LOAD_MEM(MachineType::Float32(), WASM_ZERO))});

  FOR_FLOAT32_INPUTS(i) {
    float input = i;
    int32_t expected = base::bit_cast<int32_t, float>(input);
    r.builder().WriteMemory(&memory[0], input);
    CHECK_EQ(expected, r.Call());
  }
}

WASM_EXEC_TEST(F32ReinterpretI32) {
  WasmRunner<float> r(execution_tier);
  int32_t* memory =
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));

  r.Build({WASM_F32_REINTERPRET_I32(
      WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO))});

  FOR_INT32_INPUTS(i) {
    int32_t input = i;
    float expected = base::bit_cast<float, int32_t>(input);
    r.builder().WriteMemory(&memory[0], input);
    float result = r.Call();
    if (std::isnan(expected)) {
      CHECK(std::isnan(result));
      CHECK(IsSameNan(expected, result));
    } else {
      CHECK_EQ(expected, result);
    }
  }
}

// Do not run this test in a simulator because of signalling NaN issues on ia32.
#ifndef USE_SIMULATOR

WASM_EXEC_TEST(SignallingNanSurvivesI32ReinterpretF32) {
  WasmRunner<int32_t> r(execution_tier);

  r.Build({WASM_I32_REINTERPRET_F32(
      WASM_SEQ(kExprF32Const, 0x00, 0x00, 0xA0, 0x7F))});

  // This is a signalling nan.
  CHECK_EQ(0x7FA00000, r.Call());
}

#endif

WASM_EXEC_TEST(LoadMaxUint32Offset) {
  WasmRunner<int32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);

  r.Build({WASM_LOAD_MEM_OFFSET(MachineType::Int32(),  // type
                                U32V_5(0xFFFFFFFF),    // offset
                                WASM_ZERO)});          // index

  CHECK_TRAP32(r.Call());
}

WASM_EXEC_TEST(LoadStoreLoad) {
  WasmRunner<int32_t> r(execution_tier);
  int32_t* memory =
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));

  r.Build({WASM_STORE_MEM(MachineType::Int32(), WASM_ZERO,
                          WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO)),
           WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO)});

  FOR_INT32_INPUTS(i) {
    int32_t expected = i;
    r.builder().WriteMemory(&memory[0], expected);
    CHECK_EQ(expected, r.Call());
  }
}

WASM_EXEC_TEST(UnalignedFloat32Load) {
  WasmRunner<float> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_LOAD_MEM_ALIGNMENT(MachineType::Float32(), WASM_ONE, 2)});
  r.Call();
}

WASM_EXEC_TEST(UnalignedFloat64Load) {
  WasmRunner<double> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_LOAD_MEM_ALIGNMENT(MachineType::Float64(), WASM_ONE, 3)});
  r.Call();
}

WASM_EXEC_TEST(UnalignedInt32Load) {
  WasmRunner<uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_LOAD_MEM_ALIGNMENT(MachineType::Int32(), WASM_ONE, 2)});
  r.Call();
}

WASM_EXEC_TEST(UnalignedInt32Store) {
  WasmRunner<int32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_SEQ(WASM_STORE_MEM_ALIGNMENT(MachineType::Int32(), WASM_ONE, 2,
                                             WASM_I32V_1(1)),
                    WASM_I32V_1(12))});
  r.Call();
}

WASM_EXEC_TEST(UnalignedFloat32Store) {
  WasmRunner<int32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_SEQ(WASM_STORE_MEM_ALIGNMENT(MachineType::Float32(), WASM_ONE,
                                             2, WASM_F32(1.0)),
                    WASM_I32V_1(12))});
  r.Call();
}

WASM_EXEC_TEST(UnalignedFloat64Store) {
  WasmRunner<int32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_SEQ(WASM_STORE_MEM_ALIGNMENT(MachineType::Float64(), WASM_ONE,
                                             3, WASM_F64(1.0)),
                    WASM_I32V_1(12))});
  r.Call();
}

WASM_EXEC_TEST(VoidReturn1) {
  const int32_t kExpected = -414444;
  WasmRunner<int32_t> r(execution_tier);

  // Build the test function.
  WasmFunctionCompiler& test_func = r.NewFunction<void>();
  test_func.Build({kExprNop});

  // Build the calling function.
  r.Build({WASM_CALL_FUNCTION0(test_func.function_index()),
           WASM_I32V_3(kExpected)});

  // Call and check.
  int32_t result = r.Call();
  CHECK_EQ(kExpected, result);
}

WASM_EXEC_TEST(VoidReturn2) {
  const int32_t kExpected = -414444;
  WasmRunner<int32_t> r(execution_tier);

  // Build the test function.
  WasmFunctionCompiler& test_func = r.NewFunction<void>();
  test_func.Build({WASM_RETURN0});

  // Build the calling function.
  r.Build({WASM_CALL_FUNCTION0(test_func.function_index()),
           WASM_I32V_3(kExpected)});

  // Call and check.
  int32_t result = r.Call();
  CHECK_EQ(kExpected, result);
}

WASM_EXEC_TEST(BrEmpty) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BRV(0, WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(BrIfEmpty) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BRV_IF(0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Block_empty) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({kExprBlock, kVoidCode, kExprEnd, WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Block_empty_br1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(WASM_BR(0)), WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Block_empty_brif1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK(WASM_BR_IF(0, WASM_ZERO)), WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Block_empty_brif2) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.Build({WASM_BLOCK(WASM_BR_IF(0, WASM_LOCAL_GET(1))), WASM_LOCAL_GET(0)});
  FOR_UINT32_INPUTS(i) { CHECK_EQ(i, r.Call(i, i + 1)); }
}

WASM_EXEC_TEST(Block_i) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Block_f) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_BLOCK_F(WASM_LOCAL_GET(0))});
  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Block_d) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_BLOCK_D(WASM_LOCAL_GET(0))});
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Block_br2) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_BRV(0, WASM_LOCAL_GET(0)))});
  FOR_UINT32_INPUTS(i) { CHECK_EQ(i, static_cast<uint32_t>(r.Call(i))); }
}

WASM_EXEC_TEST(Block_If_P) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // block { if (p0) break 51; 52; }
  r.Build({WASM_BLOCK_I(                      // --
      WASM_IF(WASM_LOCAL_GET(0),              // --
              WASM_BRV(1, WASM_I32V_1(51))),  // --
      WASM_I32V_1(52))});                     // --
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 51 : 52;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Loop_empty) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({kExprLoop, kVoidCode, kExprEnd, WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Loop_i) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_LOOP_I(WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Loop_f) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_LOOP_F(WASM_LOCAL_GET(0))});
  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Loop_d) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_LOOP_D(WASM_LOCAL_GET(0))});
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Loop_empty_br1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(WASM_LOOP(WASM_BR(1))), WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Loop_empty_brif1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(WASM_LOOP(WASM_BR_IF(1, WASM_ZERO))), WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Loop_empty_brif2) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.Build({WASM_LOOP_I(WASM_BRV_IF(1, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)))});
  FOR_UINT32_INPUTS(i) { CHECK_EQ(i, r.Call(i, i + 1)); }
}

WASM_EXEC_TEST(Loop_empty_brif3) {
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.Build({WASM_LOOP(WASM_BRV_IFD(1, WASM_LOCAL_GET(2), WASM_LOCAL_GET(0))),
           WASM_LOCAL_GET(1)});
  FOR_UINT32_INPUTS(i) {
    FOR_UINT32_INPUTS(j) {
      CHECK_EQ(i, r.Call(0, i, j));
      CHECK_EQ(j, r.Call(1, i, j));
    }
  }
}

WASM_EXEC_TEST(Block_BrIf_P) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_BRV_IFD(0, WASM_I32V_1(51), WASM_LOCAL_GET(0)),
                        WASM_I32V_1(52))});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 51 : 52;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Block_IfElse_P_assign) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // { if (p0) p0 = 71; else p0 = 72; return p0; }
  r.Build({WASM_IF_ELSE(WASM_LOCAL_GET(0),                    // --
                        WASM_LOCAL_SET(0, WASM_I32V_2(71)),   // --
                        WASM_LOCAL_SET(0, WASM_I32V_2(72))),  // --
           WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 71 : 72;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Block_IfElse_P_return) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // if (p0) return 81; else return 82;
  r.Build({WASM_IF_ELSE(WASM_LOCAL_GET(0),  // --
                        RET_I8(81),         // --
                        RET_I8(82)),        // --
           WASM_ZERO});                     // --
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 81 : 82;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Block_If_P_assign) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // { if (p0) p0 = 61; p0; }
  r.Build({WASM_IF(WASM_LOCAL_GET(0), WASM_LOCAL_SET(0, WASM_I32V_1(61))),
           WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 61 : i;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(DanglingAssign) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // { return 0; p0 = 0; }
  r.Build({WASM_BLOCK_I(RET_I8(99), WASM_LOCAL_TEE(0, WASM_ZERO))});
  CHECK_EQ(99, r.Call(1));
}

WASM_EXEC_TEST(ExprIf_P) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // p0 ? 11 : 22;
  r.Build({WASM_IF_ELSE_I(WASM_LOCAL_GET(0),   // --
                          WASM_I32V_1(11),     // --
                          WASM_I32V_1(22))});  // --
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 11 : 22;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(CountDown) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_LOOP(WASM_IF(WASM_LOCAL_GET(0),
                             WASM_LOCAL_SET(0, WASM_I32_SUB(WASM_LOCAL_GET(0),
                                                            WASM_I32V_1(1))),
                             WASM_BR(1))),
           WASM_LOCAL_GET(0)});
  CHECK_EQ(0, r.Call(1));
  CHECK_EQ(0, r.Call(10));
  CHECK_EQ(0, r.Call(100));
}

WASM_EXEC_TEST(CountDown_fallthru) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build(
      {WASM_LOOP(
           WASM_IF(WASM_NOT(WASM_LOCAL_GET(0)), WASM_BRV(2, WASM_LOCAL_GET(0))),
           WASM_LOCAL_SET(0, WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V_1(1))),
           WASM_CONTINUE(0)),
       WASM_LOCAL_GET(0)});
  CHECK_EQ(0, r.Call(1));
  CHECK_EQ(0, r.Call(10));
  CHECK_EQ(0, r.Call(100));
}

WASM_EXEC_TEST(WhileCountDown) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_WHILE(WASM_LOCAL_GET(0),
                      WASM_LOCAL_SET(
                          0, WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V_1(1)))),
           WASM_LOCAL_GET(0)});
  CHECK_EQ(0, r.Call(1));
  CHECK_EQ(0, r.Call(10));
  CHECK_EQ(0, r.Call(100));
}

WASM_EXEC_TEST(Loop_if_break1) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_LOOP(WASM_IF(WASM_LOCAL_GET(0), WASM_BRV(2, WASM_LOCAL_GET(1))),
                     WASM_LOCAL_SET(0, WASM_I32V_2(99))),
           WASM_LOCAL_GET(0)});
  CHECK_EQ(99, r.Call(0, 11));
  CHECK_EQ(65, r.Call(3, 65));
  CHECK_EQ(10001, r.Call(10000, 10001));
  CHECK_EQ(-29, r.Call(-28, -29));
}

WASM_EXEC_TEST(Loop_if_break2) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_LOOP(WASM_BRV_IF(1, WASM_LOCAL_GET(1), WASM_LOCAL_GET(0)),
                     WASM_DROP, WASM_LOCAL_SET(0, WASM_I32V_2(99))),
           WASM_LOCAL_GET(0)});
  CHECK_EQ(99, r.Call(0, 33));
  CHECK_EQ(3, r.Call(1, 3));
  CHECK_EQ(10000, r.Call(99, 10000));
  CHECK_EQ(-29, r.Call(-11, -29));
}

WASM_EXEC_TEST(Loop_if_break_fallthru) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(WASM_LOOP(WASM_IF(WASM_LOCAL_GET(0), WASM_BR(2)),
                        WASM_LOCAL_SET(0, WASM_I32V_2(93)))),
           WASM_LOCAL_GET(0)});
  CHECK_EQ(93, r.Call(0));
  CHECK_EQ(3, r.Call(3));
  CHECK_EQ(10001, r.Call(10001));
  CHECK_EQ(-22, r.Call(-22));
}

WASM_EXEC_TEST(Loop_if_break_fallthru2) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(B1(WASM_LOOP(WASM_IF(WASM_LOCAL_GET(0), WASM_BR(2)),
                           WASM_LOCAL_SET(0, WASM_I32V_2(93))))),
           WASM_LOCAL_GET(0)});
  CHECK_EQ(93, r.Call(0));
  CHECK_EQ(3, r.Call(3));
  CHECK_EQ(10001, r.Call(10001));
  CHECK_EQ(-22, r.Call(-22));
}

WASM_EXEC_TEST(IfBreak1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_IF(WASM_LOCAL_GET(0), WASM_SEQ(WASM_BR(0), WASM_UNREACHABLE)),
           WASM_I32V_2(91)});
  CHECK_EQ(91, r.Call(0));
  CHECK_EQ(91, r.Call(1));
  CHECK_EQ(91, r.Call(-8734));
}

WASM_EXEC_TEST(IfBreak2) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_IF(WASM_LOCAL_GET(0), WASM_SEQ(WASM_BR(0), RET_I8(77))),
           WASM_I32V_2(81)});
  CHECK_EQ(81, r.Call(0));
  CHECK_EQ(81, r.Call(1));
  CHECK_EQ(81, r.Call(-8734));
}

WASM_EXEC_TEST(LoadMemI32) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  int32_t* memory =
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
  r.builder().RandomizeMemory(1111);

  r.Build({WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO)});

  r.builder().WriteMemory(&memory[0], 99999999);
  CHECK_EQ(99999999, r.Call(0));

  r.builder().WriteMemory(&memory[0], 88888888);
  CHECK_EQ(88888888, r.Call(0));

  r.builder().WriteMemory(&memory[0], 77777777);
  CHECK_EQ(77777777, r.Call(0));
}

WASM_EXEC_TEST(LoadMemI32_alignment) {
  for (uint8_t alignment = 0; alignment <= 2; ++alignment) {
    WasmRunner<int32_t, int32_t> r(execution_tier);
    int32_t* memory =
        r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
    r.builder().RandomizeMemory(1111);

    r.Build(
        {WASM_LOAD_MEM_ALIGNMENT(MachineType::Int32(), WASM_ZERO, alignment)});

    r.builder().WriteMemory(&memory[0], 0x1A2B3C4D);
    CHECK_EQ(0x1A2B3C4D, r.Call(0));

    r.builder().WriteMemory(&memory[0], 0x5E6F7A8B);
    CHECK_EQ(0x5E6F7A8B, r.Call(0));

    r.builder().WriteMemory(&memory[0], 0x7CA0B1C2);
    CHECK_EQ(0x7CA0B1C2, r.Call(0));
  }
}

WASM_EXEC_TEST(LoadMemI32_oob) {
  WasmRunner<int32_t, uint32_t> r(execution_tier);
  int32_t* memory =
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
  r.builder().RandomizeMemory(1111);

  r.Build({WASM_LOAD_MEM(MachineType::Int32(), WASM_LOCAL_GET(0))});

  r.builder().WriteMemory(&memory[0], 88888888);
  CHECK_EQ(88888888, r.Call(0u));
  for (uint32_t offset = kWasmPageSize - 3; offset < kWasmPageSize + 40;
       ++offset) {
    CHECK_TRAP(r.Call(offset));
  }

  for (uint32_t offset = 0x80000000; offset < 0x80000010; ++offset) {
    CHECK_TRAP(r.Call(offset));
  }
}

WASM_EXEC_TEST(LoadMem_offset_oob) {
  static const MachineType machineTypes[] = {
      MachineType::Int8(),   MachineType::Uint8(),  MachineType::Int16(),
      MachineType::Uint16(), MachineType::Int32(),  MachineType::Uint32(),
      MachineType::Int64(),  MachineType::Uint64(), MachineType::Float32(),
      MachineType::Float64()};

  constexpr size_t num_bytes = kWasmPageSize;

  for (size_t m = 0; m < arraysize(machineTypes); ++m) {
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    r.builder().AddMemoryElems<uint8_t>(num_bytes);
    r.builder().RandomizeMemory(1116 + static_cast<int>(m));

    constexpr uint8_t kOffset = 8;
    uint32_t boundary = num_bytes - kOffset - machineTypes[m].MemSize();

    r.Build({WASM_LOAD_MEM_OFFSET(machineTypes[m], kOffset, WASM_LOCAL_GET(0)),
             WASM_DROP, WASM_ZERO});

    CHECK_EQ(0, r.Call(boundary));  // in bounds.

    for (uint32_t offset = boundary + 1; offset < boundary + 19; ++offset) {
      CHECK_TRAP(r.Call(offset));  // out of bounds.
    }
  }
}

WASM_EXEC_TEST(LoadMemI32_offset) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  int32_t* memory =
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
  r.builder().RandomizeMemory(1111);

  r.Build({WASM_LOAD_MEM_OFFSET(MachineType::Int32(), 4, WASM_LOCAL_GET(0))});

  r.builder().WriteMemory(&memory[0], 66666666);
  r.builder().WriteMemory(&memory[1], 77777777);
  r.builder().WriteMemory(&memory[2], 88888888);
  r.builder().WriteMemory(&memory[3], 99999999);
  CHECK_EQ(77777777, r.Call(0));
  CHECK_EQ(88888888, r.Call(4));
  CHECK_EQ(99999999, r.Call(8));

  r.builder().WriteMemory(&memory[0], 11111111);
  r.builder().WriteMemory(&memory[1], 22222222);
  r.builder().WriteMemory(&memory[2], 33333333);
  r.builder().WriteMemory(&memory[3], 44444444);
  CHECK_EQ(22222222, r.Call(0));
  CHECK_EQ(33333333, r.Call(4));
  CHECK_EQ(44444444, r.Call(8));
}

WASM_EXEC_TEST(LoadMemI32_const_oob_misaligned) {
  // This test accesses memory starting at kRunwayLength bytes before the end of
  // the memory until a few bytes beyond.
  constexpr uint8_t kRunwayLength = 12;
  // TODO(titzer): Fix misaligned accesses on MIPS and re-enable.
  for (uint8_t offset = 0; offset < kRunwayLength + 5; ++offset) {
    for (uint32_t index = kWasmPageSize - kRunwayLength;
         index < kWasmPageSize + 5; ++index) {
      WasmRunner<int32_t> r(execution_tier);
      r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);
      r.builder().RandomizeMemory();

      r.Build({WASM_LOAD_MEM_OFFSET(MachineType::Int32(), offset,
                                    WASM_I32V_3(index))});

      if (offset + index + sizeof(int32_t) <= kWasmPageSize) {
        CHECK_EQ(r.builder().raw_val_at<int32_t>(offset + index), r.Call());
      } else {
        CHECK_TRAP(r.Call());
      }
    }
  }
}

WASM_EXEC_TEST(LoadMemI32_const_oob) {
  // This test accesses memory starting at kRunwayLength bytes before the end of
  // the memory until a few bytes beyond.
  constexpr uint8_t kRunwayLength = 24;
  for (uint8_t offset = 0; offset < kRunwayLength + 5; offset += 4) {
    for (uint32_t index = kWasmPageSize - kRunwayLength;
         index < kWasmPageSize + 5; index += 4) {
      WasmRunner<int32_t> r(execution_tier);
      r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);
      r.builder().RandomizeMemory();

      r.Build({WASM_LOAD_MEM_OFFSET(MachineType::Int32(), offset,
                                    WASM_I32V_3(index))});

      if (offset + index + sizeof(int32_t) <= kWasmPageSize) {
        CHECK_EQ(r.builder().raw_val_at<int32_t>(offset + index), r.Call());
      } else {
        CHECK_TRAP(r.Call());
      }
    }
  }
}

WASM_EXEC_TEST(StoreMemI32_alignment) {
  const int32_t kWritten = 0x12345678;

  for (uint8_t i = 0; i <= 2; ++i) {
    WasmRunner<int32_t, int32_t> r(execution_tier);
    int32_t* memory =
        r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
    r.Build({WASM_STORE_MEM_ALIGNMENT(MachineType::Int32(), WASM_ZERO, i,
                                      WASM_LOCAL_GET(0)),
             WASM_LOCAL_GET(0)});
    r.builder().RandomizeMemory(1111);
    memory[0] = 0;

    CHECK_EQ(kWritten, r.Call(kWritten));
    CHECK_EQ(kWritten, r.builder().ReadMemory(&memory[0]));
  }
}

WASM_EXEC_TEST(StoreMemI32_offset) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  int32_t* memory =
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
  const int32_t kWritten = 0xAABBCCDD;

  r.Build({WASM_STORE_MEM_OFFSET(MachineType::Int32(), 4, WASM_LOCAL_GET(0),
                                 WASM_I32V_5(kWritten)),
           WASM_I32V_5(kWritten)});

  for (int i = 0; i < 2; ++i) {
    r.builder().RandomizeMemory(1111);
    r.builder().WriteMemory(&memory[0], 66666666);
    r.builder().WriteMemory(&memory[1], 77777777);
    r.builder().WriteMemory(&memory[2], 88888888);
    r.builder().WriteMemory(&memory[3], 99999999);
    CHECK_EQ(kWritten, r.Call(i * 4));
    CHECK_EQ(66666666, r.builder().ReadMemory(&memory[0]));
    CHECK_EQ(i == 0 ? kWritten : 77777777, r.builder().ReadMemory(&memory[1]));
    CHECK_EQ(i == 1 ? kWritten : 88888888, r.builder().ReadMemory(&memory[2]));
    CHECK_EQ(i == 2 ? kWritten : 99999999, r.builder().ReadMemory(&memory[3]));
  }
}

WASM_EXEC_TEST(StoreMem_offset_oob) {
  // 64-bit cases are handled in test-run-wasm-64.cc
  static const MachineType machineTypes[] = {
      MachineType::Int8(),    MachineType::Uint8(),  MachineType::Int16(),
      MachineType::Uint16(),  MachineType::Int32(),  MachineType::Uint32(),
      MachineType::Float32(), MachineType::Float64()};

  constexpr size_t num_bytes = kWasmPageSize;

  for (size_t m = 0; m < arraysize(machineTypes); ++m) {
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(num_bytes);

    r.builder().RandomizeMemory(1119 + static_cast<int>(m));

    r.Build({WASM_STORE_MEM_OFFSET(machineTypes[m], 8, WASM_LOCAL_GET(0),
                                   WASM_LOAD_MEM(machineTypes[m], WASM_ZERO)),
             WASM_ZERO});

    uint8_t memsize = machineTypes[m].MemSize();
    uint32_t boundary = num_bytes - 8 - memsize;
    CHECK_EQ(0, r.Call(boundary));  // in bounds.
    CHECK_EQ(0, memcmp(&memory[0], &memory[8 + boundary], memsize));

    for (uint32_t offset = boundary + 1; offset < boundary + 19; ++offset) {
      CHECK_TRAP(r.Call(offset));  // out of bounds.
    }
  }
}

WASM_EXEC_TEST(Store_i32_narrowed) {
  constexpr uint8_t kOpcodes[] = {kExprI32StoreMem8, kExprI32StoreMem16,
                                  kExprI32StoreMem};
  int stored_size_in_bytes = 0;
  for (auto opcode : kOpcodes) {
    stored_size_in_bytes = std::max(1, stored_size_in_bytes * 2);
    constexpr int kBytes = 24;
    uint8_t expected_memory[kBytes] = {0};
    WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
    uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);
    constexpr uint32_t kPattern = 0x12345678;

    r.Build({WASM_LOCAL_GET(0),                    // index
             WASM_LOCAL_GET(1),                    // value
             opcode, ZERO_ALIGNMENT, ZERO_OFFSET,  // store
             WASM_ZERO});                          // return value

    for (int i = 0; i <= kBytes - stored_size_in_bytes; ++i) {
      uint32_t pattern = base::bits::RotateLeft32(kPattern, i % 32);
      r.Call(i, pattern);
      for (int b = 0; b < stored_size_in_bytes; ++b) {
        expected_memory[i + b] = static_cast<uint8_t>(pattern >> (b * 8));
      }
      for (int w = 0; w < kBytes; ++w) {
        CHECK_EQ(expected_memory[w], memory[w]);
      }
    }
  }
}

WASM_EXEC_TEST(LoadMemI32_P) {
  const int kNumElems = 8;
  WasmRunner<int32_t, int32_t> r(execution_tier);
  int32_t* memory =
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
  r.builder().RandomizeMemory(2222);

  r.Build({WASM_LOAD_MEM(MachineType::Int32(), WASM_LOCAL_GET(0))});

  for (int i = 0; i < kNumElems; ++i) {
    CHECK_EQ(r.builder().ReadMemory(&memory[i]), r.Call(i * 4));
  }
}

WASM_EXEC_TEST(MemI32_Sum) {
  const int kNumElems = 20;
  WasmRunner<uint32_t, int32_t> r(execution_tier);
  uint32_t* memory =
      r.builder().AddMemoryElems<uint32_t>(kWasmPageSize / sizeof(int32_t));
  const uint8_t kSum = r.AllocateLocal(kWasmI32);

  r.Build(
      {WASM_WHILE(
           WASM_LOCAL_GET(0),
           WASM_BLOCK(WASM_LOCAL_SET(
                          kSum, WASM_I32_ADD(WASM_LOCAL_GET(kSum),
                                             WASM_LOAD_MEM(MachineType::Int32(),
                                                           WASM_LOCAL_GET(0)))),
                      WASM_LOCAL_SET(
                          0, WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V_1(4))))),
       WASM_LOCAL_GET(1)});

  // Run 4 trials.
  for (int i = 0; i < 3; ++i) {
    r.builder().RandomizeMemory(i * 33);
    uint32_t expected = 0;
    for (size_t j = kNumElems - 1; j > 0; --j) {
      expected += r.builder().ReadMemory(&memory[j]);
    }
    uint32_t result = r.Call(4 * (kNumElems - 1));
    CHECK_EQ(expected, result);
  }
}

WASM_EXEC_TEST(CheckMachIntsZero) {
  cons
"""


```