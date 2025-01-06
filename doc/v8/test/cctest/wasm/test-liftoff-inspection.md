Response: The user wants to understand the functionality of the C++ source code file `v8/test/cctest/wasm/test-liftoff-inspection.cc`.

Here's a breakdown of the thought process to summarize the code and provide a JavaScript example:

1. **Identify the Core Purpose:** The file name "test-liftoff-inspection.cc" and the inclusion of headers like `"src/wasm/baseline/liftoff-compiler.h"` strongly suggest this file is for testing the inspection capabilities of the Liftoff compiler, V8's baseline WebAssembly compiler.

2. **Analyze the Test Structure:**  Notice the use of `TEST()` macros, which are common in C++ testing frameworks. This confirms it's a test file. The tests seem to focus on two main aspects:
    * **Deterministic Compilation:** Tests with names like "Liftoff_deterministic_simple" check if Liftoff produces the same machine code when compiling the same WebAssembly code multiple times.
    * **Debug Side Table Generation:** Tests with names like "Liftoff_debug_side_table_simple" and "Liftoff_breakpoint_simple" focus on the generation of debug information (DebugSideTable) by the Liftoff compiler. This information is crucial for debugging WebAssembly code.

3. **Examine the `LiftoffCompileEnvironment` Class:** This class appears to be a test fixture, providing a controlled environment for Liftoff compilation. Key functionalities include:
    * Building WebAssembly modules using `WasmRunnerBase`.
    * Compiling WebAssembly functions using `ExecuteLiftoffCompilation`.
    * Generating debug side tables using `GenerateLiftoffDebugSideTable`.
    * Methods to check for deterministic compilation (`CheckDeterministicCompilation`).
    * Methods to generate and verify debug side tables (`GenerateDebugSideTable`, `CheckDebugSideTable`).

4. **Understand the Debug Side Table Tests:**  These tests define expected `DebugSideTableEntry` objects. Each entry represents the state of the WebAssembly execution at a particular point (identified by PC offset, though not explicitly exposed in the assertions). The entries track the stack height and the location of local variables (registers, stack, or constants). The tests assert that the generated debug side table matches the expected entries.

5. **Connect to JavaScript Debugging:** The purpose of the debug side table becomes clear: it enables debugging WebAssembly code in JavaScript environments. When a breakpoint is hit or an error occurs, the JavaScript debugger needs information about the current state of the WebAssembly execution, such as the values of local variables and the call stack. The debug side table provides this mapping between the WebAssembly bytecode and the runtime state.

6. **Formulate the Summary:**  Combine the observations to create a concise summary: The file tests the Liftoff compiler's ability to generate consistent machine code and accurate debugging information. This debugging information is crucial for JavaScript environments to inspect the state of WebAssembly execution.

7. **Create a JavaScript Example:**  To illustrate the connection to JavaScript, demonstrate a simple WebAssembly module and how a JavaScript debugger might interact with it. The example should involve setting a breakpoint and inspecting a variable, showcasing the practical application of the debug information being tested in the C++ file. A simple addition function is a good choice for the WebAssembly module.

8. **Refine and Review:**  Ensure the summary is clear, accurate, and easy to understand. Check that the JavaScript example is relevant and demonstrates the connection effectively. Double-check for any technical inaccuracies.
这个C++源代码文件 `v8/test/cctest/wasm/test-liftoff-inspection.cc` 的主要功能是**测试 V8 的 Liftoff 编译器在生成调试信息方面的能力**。具体来说，它测试了以下两个方面：

1. **Liftoff 编译器的确定性 (Deterministic Compilation):**  测试 Liftoff 编译器对于相同的 WebAssembly 代码，是否能够生成相同的机器码。这意味着重复编译同一个函数应该产生完全一致的结果。这是为了确保编译过程的可预测性和可靠性。

2. **Liftoff 编译器生成的调试边表 (Debug Side Table):**  测试 Liftoff 编译器是否能够正确地生成用于调试的辅助信息，即调试边表。这个边表记录了程序执行过程中的关键状态信息，例如局部变量的位置（寄存器、栈或常量）、栈的高度等。这些信息对于在调试器中单步执行 WebAssembly 代码、查看变量值至关重要。

**与 JavaScript 的关系以及 JavaScript 示例:**

这个 C++ 文件直接测试的是 V8 引擎内部的 Liftoff 编译器，但它与 JavaScript 的功能密切相关，因为 **WebAssembly 代码通常是在 JavaScript 环境中运行的**。当我们在 JavaScript 中运行 WebAssembly 代码并使用开发者工具进行调试时，V8 引擎会利用 Liftoff 编译器生成的调试边表来提供调试信息。

**JavaScript 示例:**

假设我们有以下简单的 WebAssembly 代码 (用 WAT 格式表示)：

```wat
(module
  (func $add (param $p1 i32) (param $p2 i32) (result i32)
    local.get $p1
    local.get $p2
    i32.add
  )
  (export "add" (func $add))
)
```

这个 WebAssembly 模块定义了一个名为 `add` 的函数，它接受两个 i32 类型的参数并返回它们的和。

在 JavaScript 中，我们可以加载并运行这个 WebAssembly 模块：

```javascript
async function runWasm() {
  const response = await fetch('path/to/your/module.wasm'); // 假设你有一个编译好的 wasm 文件
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  const result = instance.exports.add(5, 10);
  console.log(result); // 输出 15
}

runWasm();
```

**调试过程与 Liftoff 调试边表的关系:**

当我们在这个 JavaScript 代码中设置断点，例如在调用 `instance.exports.add(5, 10)` 之后，并且单步进入 WebAssembly 函数 `add` 时，JavaScript 开发者工具会显示 WebAssembly 代码的执行状态。这包括：

* **当前的执行位置:** 指向 `local.get $p1` 指令。
* **局部变量的值:** 可以查看到 `$p1` 的值为 5， `$p2` 的值为 10。
* **栈的状态 (如果工具支持):** 可能会显示当前的运算栈为空。

**Liftoff 调试边表的作用就在于此:**  当 Liftoff 编译器编译 `add` 函数时，它会生成一个调试边表。这个边表会记录，例如在 `local.get $p1` 指令执行前，局部变量 `$p1` 和 `$p2` 可能被分配在特定的寄存器中。当调试器请求这些信息时，V8 引擎会查找这个调试边表，从而将 WebAssembly 的内部状态映射到我们可以理解的调试信息。

**`test-liftoff-inspection.cc` 中的测试是如何模拟这个过程的:**

这个 C++ 测试文件通过 `LiftoffCompileEnvironment` 类模拟了 Liftoff 的编译过程，并人为构造了一些 WebAssembly 代码片段。然后，它会检查：

* **确定性测试:** 重复编译相同的代码，比较生成的机器码是否一致。
* **调试边表测试:**  它会编译 WebAssembly 代码，并期望 Liftoff 编译器生成特定的 `DebugSideTable` 内容。例如，它会断言在执行某个指令前后，某些局部变量应该位于寄存器中、栈上或者是一个常量值。`CheckDebugSideTable` 函数就是用来比对实际生成的调试边表和预期的调试边表是否一致的。

总而言之，`test-liftoff-inspection.cc` 是 V8 引擎中一个非常重要的测试文件，它确保了 Liftoff 编译器在生成可预测的机器码和准确的调试信息方面是可靠的，这对于在 JavaScript 环境中高效地调试 WebAssembly 代码至关重要。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-liftoff-inspection.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/baseline/liftoff-compiler.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/wasm-debug.h"
#include "test/cctest/cctest.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8 {
namespace internal {
namespace wasm {

namespace {

class LiftoffCompileEnvironment {
 public:
  LiftoffCompileEnvironment()
      : isolate_(CcTest::InitIsolateOnce()),
        handle_scope_(isolate_),
        zone_(isolate_->allocator(), ZONE_NAME),
        wasm_runner_(nullptr, kWasmOrigin, TestExecutionTier::kLiftoff, 0) {
    // Add a table of length 1, for indirect calls.
    wasm_runner_.builder().AddIndirectFunctionTable(nullptr, 1);
    // Set tiered down such that we generate debugging code.
    wasm_runner_.builder().SetDebugState();
  }

  struct TestFunction {
    WasmCode* code;
    FunctionBody body;
  };

  void CheckDeterministicCompilation(
      std::initializer_list<ValueType> return_types,
      std::initializer_list<ValueType> param_types,
      std::initializer_list<uint8_t> raw_function_bytes) {
    auto test_func = AddFunction(return_types, param_types, raw_function_bytes);

    // Now compile the function with Liftoff two times.
    CompilationEnv env = CompilationEnv::ForModule(
        wasm_runner_.builder().trusted_instance_data()->native_module());
    WasmDetectedFeatures detected1;
    WasmDetectedFeatures detected2;
    WasmCompilationResult result1 =
        ExecuteLiftoffCompilation(&env, test_func.body,
                                  LiftoffOptions{}
                                      .set_func_index(test_func.code->index())
                                      .set_detected_features(&detected1));
    WasmCompilationResult result2 =
        ExecuteLiftoffCompilation(&env, test_func.body,
                                  LiftoffOptions{}
                                      .set_func_index(test_func.code->index())
                                      .set_detected_features(&detected2));

    CHECK(result1.succeeded());
    CHECK(result2.succeeded());

    // Check that the generated code matches.
    auto code1 =
        base::VectorOf(result1.code_desc.buffer, result1.code_desc.instr_size);
    auto code2 =
        base::VectorOf(result2.code_desc.buffer, result2.code_desc.instr_size);
    CHECK_EQ(code1, code2);
    CHECK_EQ(detected1, detected2);
  }

  std::unique_ptr<DebugSideTable> GenerateDebugSideTable(
      std::initializer_list<ValueType> return_types,
      std::initializer_list<ValueType> param_types,
      std::initializer_list<uint8_t> raw_function_bytes,
      std::vector<int> breakpoints = {}) {
    auto test_func = AddFunction(return_types, param_types, raw_function_bytes);

    CompilationEnv env = CompilationEnv::ForModule(
        wasm_runner_.builder().trusted_instance_data()->native_module());
    std::unique_ptr<DebugSideTable> debug_side_table_via_compilation;
    auto result = ExecuteLiftoffCompilation(
        &env, test_func.body,
        LiftoffOptions{}
            .set_func_index(0)
            .set_for_debugging(kForDebugging)
            .set_breakpoints(base::VectorOf(breakpoints))
            .set_debug_sidetable(&debug_side_table_via_compilation));
    CHECK(result.succeeded());

    // If there are no breakpoint, then {ExecuteLiftoffCompilation} should
    // provide the same debug side table.
    if (breakpoints.empty()) {
      std::unique_ptr<DebugSideTable> debug_side_table =
          GenerateLiftoffDebugSideTable(test_func.code);
      CheckTableEquals(*debug_side_table, *debug_side_table_via_compilation);
    }

    return debug_side_table_via_compilation;
  }

  TestingModuleBuilder* builder() { return &wasm_runner_.builder(); }

 private:
  static void CheckTableEquals(const DebugSideTable& a,
                               const DebugSideTable& b) {
    CHECK_EQ(a.num_locals(), b.num_locals());
    CHECK_EQ(a.entries().size(), b.entries().size());
    CHECK(std::equal(a.entries().begin(), a.entries().end(),
                     b.entries().begin(), b.entries().end(),
                     &CheckEntryEquals));
  }

  static bool CheckEntryEquals(const DebugSideTable::Entry& a,
                               const DebugSideTable::Entry& b) {
    CHECK_EQ(a.pc_offset(), b.pc_offset());
    CHECK_EQ(a.stack_height(), b.stack_height());
    CHECK_EQ(a.changed_values(), b.changed_values());
    return true;
  }

  FunctionSig* AddSig(std::initializer_list<ValueType> return_types,
                      std::initializer_list<ValueType> param_types) {
    ValueType* storage = zone_.AllocateArray<ValueType>(return_types.size() +
                                                        param_types.size());
    std::copy(return_types.begin(), return_types.end(), storage);
    std::copy(param_types.begin(), param_types.end(),
              storage + return_types.size());
    FunctionSig* sig = zone_.New<FunctionSig>(return_types.size(),
                                              param_types.size(), storage);
    return sig;
  }

  TestFunction AddFunction(std::initializer_list<ValueType> return_types,
                           std::initializer_list<ValueType> param_types,
                           std::initializer_list<uint8_t> function_bytes) {
    FunctionSig* sig = AddSig(return_types, param_types);
    // Compile the function so we can get the WasmCode* which is later used to
    // generate the debug side table lazily.
    auto& func_compiler = wasm_runner_.NewFunction(sig, "f");
    func_compiler.Build(base::VectorOf(function_bytes));

    WasmCode* code =
        wasm_runner_.builder().GetFunctionCode(func_compiler.function_index());

    // Get the wire bytes created by the function compiler (including locals
    // declaration and the trailing "end" opcode).
    NativeModule* native_module = code->native_module();
    auto* function = &native_module->module()->functions[code->index()];
    base::Vector<const uint8_t> function_wire_bytes =
        native_module->wire_bytes().SubVector(function->code.offset(),
                                              function->code.end_offset());

    bool is_shared =
        native_module->module()->type(function->sig_index).is_shared;
    FunctionBody body{sig, 0, function_wire_bytes.begin(),
                      function_wire_bytes.end(), is_shared};
    return {code, body};
  }

  Isolate* isolate_;
  HandleScope handle_scope_;
  Zone zone_;
  // wasm_runner_ is used to build actual code objects needed to request lazy
  // generation of debug side tables.
  WasmRunnerBase wasm_runner_;
  WasmCodeRefScope code_ref_scope_;
};

struct DebugSideTableEntry {
  int stack_height;
  std::vector<DebugSideTable::Entry::Value> changed_values;

  // Construct via vector or implicitly via initializer list.
  DebugSideTableEntry(int stack_height,
                      std::vector<DebugSideTable::Entry::Value> changed_values)
      : stack_height(stack_height), changed_values(std::move(changed_values)) {}

  DebugSideTableEntry(
      int stack_height,
      std::initializer_list<DebugSideTable::Entry::Value> changed_values)
      : stack_height(stack_height), changed_values(changed_values) {}

  bool operator==(const DebugSideTableEntry& other) const {
    return stack_height == other.stack_height &&
           std::equal(changed_values.begin(), changed_values.end(),
                      other.changed_values.begin(), other.changed_values.end(),
                      CheckValueEquals);
  }

  // Check for equality, but ignore exact register and stack offset.
  static bool CheckValueEquals(const DebugSideTable::Entry::Value& a,
                               const DebugSideTable::Entry::Value& b) {
    return a.index == b.index && a.type == b.type && a.storage == b.storage &&
           (a.storage != DebugSideTable::Entry::kConstant ||
            a.i32_const == b.i32_const);
  }
};

// Debug builds will print the vector of DebugSideTableEntry.
#ifdef DEBUG
std::ostream& operator<<(std::ostream& out, const DebugSideTableEntry& entry) {
  out << "stack height " << entry.stack_height << ", changed: {";
  const char* comma = "";
  for (auto& v : entry.changed_values) {
    out << comma << v.index << ":" << v.type.name() << " ";
    switch (v.storage) {
      case DebugSideTable::Entry::kConstant:
        out << "const:" << v.i32_const;
        break;
      case DebugSideTable::Entry::kRegister:
        out << "reg";
        break;
      case DebugSideTable::Entry::kStack:
        out << "stack";
        break;
    }
    comma = ", ";
  }
  return out << "}";
}

std::ostream& operator<<(std::ostream& out,
                         const std::vector<DebugSideTableEntry>& entries) {
  return out << PrintCollection(entries);
}
#endif  // DEBUG

// Named constructors to make the tests more readable.
DebugSideTable::Entry::Value Constant(int index, ValueType type,
                                      int32_t constant) {
  DebugSideTable::Entry::Value value;
  value.index = index;
  value.type = type;
  value.storage = DebugSideTable::Entry::kConstant;
  value.i32_const = constant;
  return value;
}
DebugSideTable::Entry::Value Register(int index, ValueType type) {
  DebugSideTable::Entry::Value value;
  value.index = index;
  value.type = type;
  value.storage = DebugSideTable::Entry::kRegister;
  return value;
}
DebugSideTable::Entry::Value Stack(int index, ValueType type) {
  DebugSideTable::Entry::Value value;
  value.index = index;
  value.type = type;
  value.storage = DebugSideTable::Entry::kStack;
  return value;
}

void CheckDebugSideTable(std::vector<DebugSideTableEntry> expected_entries,
                         const wasm::DebugSideTable* debug_side_table) {
  std::vector<DebugSideTableEntry> entries;
  for (auto& entry : debug_side_table->entries()) {
    entries.emplace_back(
        entry.stack_height(),
        std::vector<DebugSideTable::Entry::Value>{
            entry.changed_values().begin(), entry.changed_values().end()});
  }
  CHECK_EQ(expected_entries, entries);
}

}  // namespace

TEST(Liftoff_deterministic_simple) {
  LiftoffCompileEnvironment env;
  env.CheckDeterministicCompilation(
      {kWasmI32}, {kWasmI32, kWasmI32},
      {WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
}

TEST(Liftoff_deterministic_call) {
  LiftoffCompileEnvironment env;
  env.CheckDeterministicCompilation(
      {kWasmI32}, {kWasmI32},
      {WASM_I32_ADD(WASM_CALL_FUNCTION(0, WASM_LOCAL_GET(0)),
                    WASM_LOCAL_GET(0))});
}

TEST(Liftoff_deterministic_indirect_call) {
  LiftoffCompileEnvironment env;
  env.CheckDeterministicCompilation(
      {kWasmI32}, {kWasmI32},
      {WASM_I32_ADD(WASM_CALL_INDIRECT(0, WASM_LOCAL_GET(0), WASM_I32V_1(47)),
                    WASM_LOCAL_GET(0))});
}

TEST(Liftoff_deterministic_loop) {
  LiftoffCompileEnvironment env;
  env.CheckDeterministicCompilation(
      {kWasmI32}, {kWasmI32},
      {WASM_LOOP(WASM_BR_IF(0, WASM_LOCAL_GET(0))), WASM_LOCAL_GET(0)});
}

TEST(Liftoff_deterministic_trap) {
  LiftoffCompileEnvironment env;
  env.CheckDeterministicCompilation(
      {kWasmI32}, {kWasmI32, kWasmI32},
      {WASM_I32_DIVS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
}

TEST(Liftoff_debug_side_table_simple) {
  LiftoffCompileEnvironment env;
  auto debug_side_table = env.GenerateDebugSideTable(
      {kWasmI32}, {kWasmI32, kWasmI32},
      {WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  CheckDebugSideTable(
      {
          // function entry, locals in registers.
          {2, {Register(0, kWasmI32), Register(1, kWasmI32)}},
          // OOL stack check, locals spilled, stack still empty.
          {2, {Stack(0, kWasmI32), Stack(1, kWasmI32)}},
      },
      debug_side_table.get());
}

TEST(Liftoff_debug_side_table_call) {
  LiftoffCompileEnvironment env;
  auto debug_side_table = env.GenerateDebugSideTable(
      {kWasmI32}, {kWasmI32},
      {WASM_I32_ADD(WASM_CALL_FUNCTION(0, WASM_LOCAL_GET(0)),
                    WASM_LOCAL_GET(0))});
  CheckDebugSideTable(
      {
          // function entry, local in register.
          {1, {Register(0, kWasmI32)}},
          // call, local spilled, stack empty.
          {1, {Stack(0, kWasmI32)}},
          // OOL stack check, local spilled as before, stack empty.
          {1, {}},
      },
      debug_side_table.get());
}

TEST(Liftoff_debug_side_table_call_const) {
  LiftoffCompileEnvironment env;
  constexpr int kConst = 13;
  auto debug_side_table = env.GenerateDebugSideTable(
      {kWasmI32}, {kWasmI32},
      {WASM_LOCAL_SET(0, WASM_I32V_1(kConst)),
       WASM_I32_ADD(WASM_CALL_FUNCTION(0, WASM_LOCAL_GET(0)),
                    WASM_LOCAL_GET(0))});
  CheckDebugSideTable(
      {
          // function entry, local in register.
          {1, {Register(0, kWasmI32)}},
          // call, local is kConst.
          {1, {Constant(0, kWasmI32, kConst)}},
          // OOL stack check, local spilled.
          {1, {Stack(0, kWasmI32)}},
      },
      debug_side_table.get());
}

TEST(Liftoff_debug_side_table_indirect_call) {
  LiftoffCompileEnvironment env;
  constexpr int kConst = 47;
  auto debug_side_table = env.GenerateDebugSideTable(
      {kWasmI32}, {kWasmI32},
      {WASM_I32_ADD(
          WASM_CALL_INDIRECT(0, WASM_I32V_1(kConst), WASM_LOCAL_GET(0)),
          WASM_LOCAL_GET(0))});
  CheckDebugSideTable(
      {
          // function entry, local in register.
          {1, {Register(0, kWasmI32)}},
          // indirect call, local spilled, stack empty.
          {1, {Stack(0, kWasmI32)}},
          // OOL stack check, local still spilled.
          {1, {}},
          // OOL trap (invalid index), local still spilled, stack has {kConst,
          // kStack}.
          {3, {Constant(1, kWasmI32, kConst), Stack(2, kWasmI32)}},
          // OOL trap (sig mismatch), stack unmodified.
          {3, {}},
      },
      debug_side_table.get());
}

TEST(Liftoff_debug_side_table_loop) {
  LiftoffCompileEnvironment env;
  constexpr int kConst = 42;
  auto debug_side_table = env.GenerateDebugSideTable(
      {kWasmI32}, {kWasmI32},
      {WASM_I32V_1(kConst), WASM_LOOP(WASM_BR_IF(0, WASM_LOCAL_GET(0)))});
  CheckDebugSideTable(
      {
          // function entry, local in register.
          {1, {Register(0, kWasmI32)}},
          // OOL stack check, local spilled, stack empty.
          {1, {Stack(0, kWasmI32)}},
          // OOL loop stack check, local still spilled, stack has {kConst}.
          {2, {Constant(1, kWasmI32, kConst)}},
      },
      debug_side_table.get());
}

TEST(Liftoff_debug_side_table_trap) {
  LiftoffCompileEnvironment env;
  auto debug_side_table = env.GenerateDebugSideTable(
      {kWasmI32}, {kWasmI32, kWasmI32},
      {WASM_I32_DIVS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  CheckDebugSideTable(
      {
          // function entry, locals in registers.
          {2, {Register(0, kWasmI32), Register(1, kWasmI32)}},
          // OOL stack check, local spilled, stack empty.
          {2, {Stack(0, kWasmI32), Stack(1, kWasmI32)}},
          // OOL trap (div by zero), stack as before.
          {2, {}},
          // OOL trap (unrepresentable), stack as before.
          {2, {}},
      },
      debug_side_table.get());
}

TEST(Liftoff_breakpoint_simple) {
  LiftoffCompileEnvironment env;
  // Set two breakpoints. At both locations, values are live in registers.
  auto debug_side_table = env.GenerateDebugSideTable(
      {kWasmI32}, {kWasmI32, kWasmI32},
      {WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))},
      {
          1,  // break at beginning of function (first local.get)
          5   // break at i32.add
      });
  CheckDebugSideTable(
      {
          // First break point, locals in registers.
          {2, {Register(0, kWasmI32), Register(1, kWasmI32)}},
          // Second break point, locals unchanged, two register stack values.
          {4, {Register(2, kWasmI32), Register(3, kWasmI32)}},
          // OOL stack check, locals spilled, stack empty.
          {2, {Stack(0, kWasmI32), Stack(1, kWasmI32)}},
      },
      debug_side_table.get());
}

TEST(Liftoff_debug_side_table_catch_all) {
  LiftoffCompileEnvironment env;
  TestSignatures sigs;
  int ex = env.builder()->AddException(sigs.v_v());
  ValueType exception_type = ValueType::Ref(HeapType::kAny);
  auto debug_side_table = env.GenerateDebugSideTable(
      {}, {kWasmI32},
      {WASM_TRY_CATCH_ALL_T(kWasmI32, WASM_STMTS(WASM_I32V(0), WASM_THROW(ex)),
                            WASM_I32V(1)),
       WASM_DROP},
      {
          18  // Break at the end of the try block.
      });
  CheckDebugSideTable(
      {
          // function entry.
          {1, {Register(0, kWasmI32)}},
          // throw.
          {2, {Stack(0, kWasmI32), Constant(1, kWasmI32, 0)}},
          // breakpoint.
          {3, {Register(1, exception_type), Constant(2, kWasmI32, 1)}},
          {1, {}},
      },
      debug_side_table.get());
}

TEST(Regress1199526) {
  LiftoffCompileEnvironment env;
  ValueType exception_type = ValueType::Ref(HeapType::kAny);
  auto debug_side_table = env.GenerateDebugSideTable(
      {}, {},
      {kExprTry, kVoidCode, kExprCallFunction, 0, kExprCatchAll, kExprLoop,
       kVoidCode, kExprEnd, kExprEnd},
      {});
  CheckDebugSideTable(
      {
          // function entry.
          {0, {}},
          // break on entry.
          {0, {}},
          // function call.
          {0, {}},
          // loop stack check.
          {1, {Stack(0, exception_type)}},
      },
      debug_side_table.get());
}

}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```