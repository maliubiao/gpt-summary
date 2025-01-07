Response:
Let's break down the thought process to analyze the C++ code and generate the detailed explanation.

1. **Understand the Goal:** The primary goal is to analyze the given C++ code (`globals.cc`) within the context of V8's WebAssembly API testing and explain its functionality, relation to JavaScript, potential errors, etc.

2. **Initial Code Scan (Keywords and Structure):**
   - Look for key terms related to WebAssembly: `wasm`, `Global`, `Import`, `Export`, `Function`, `ValType`, `GlobalType`, `Instantiate`, `call`. These immediately signal the code's purpose.
   - Observe the overall structure:  It's a C++ test using the `TEST_F` macro, indicating a testing framework (likely Google Test, as used in Chromium/V8). The test is named `Globals`, strongly suggesting it's testing WebAssembly global variables.
   - Notice the namespaces: `v8::internal::wasm`. This confirms it's internal V8 code related to WebAssembly.

3. **Deconstruct the `TEST_F` Function:**  The core logic resides within this function. Process it section by section.

   - **Global Definitions (Imports and Exports):**
     - `AddGlobalImport`:  This function clearly defines imported globals. Pay attention to the arguments: name, type (`kWasmF32`, `kWasmI64`), and mutability (`kImmutable`, `kMutable`). Document these differences.
     - `AddExportedGlobal`: This defines exported globals, including an initial value via `WasmInitExpr`. Note the similarities and differences with imports.
     - *Key Insight:* The code is setting up both imported and exported globals with different data types (float and integer) and mutability.

   - **Function Definitions (Getters and Setters):**
     - Observe the pattern:  Functions are added using `AddExportedFunction`. Their names indicate their purpose (e.g., "get const f32 import").
     - Examine the function bodies (`gcfi`, `gcii`, etc.):  They use `WASM_GLOBAL_GET` and `WASM_GLOBAL_SET` opcodes. This confirms they are interacting with the previously defined globals.
     - Note the function signatures (`FunctionSig`): They specify the return type and parameter types.
     - *Key Insight:*  The code defines functions to read and write the global variables, mimicking how a WebAssembly module interacts with its globals.

   - **Instantiation and Import Creation:**
     - `Global::make`: This creates concrete global instances for the imports. The `Val::f32` and `Val::i64` calls provide the initial values for the imports *from the host environment*.
     - `Extern* imports[]`:  This array bundles the created import globals.
     - `Instantiate(imports)`: This crucial step links the imported globals with the module definition.
     - *Key Insight:*  This section demonstrates how the host environment (C++ code) provides values for the imported WebAssembly globals.

   - **Export Retrieval:**
     - `GetExportedGlobal` and `GetExportedFunction`: These are used to obtain references to the exported globals and functions after instantiation.

   - **Testing and Verification (EXPECT_EQ):**
     - The rest of the code focuses on verifying the behavior of the globals:
       - Checking initial values (both directly via `global->get()` and indirectly via exported getter functions).
       - Modifying mutable globals via the API (`global->set()`).
       - Modifying mutable globals via exported setter functions.
       - Re-checking values after modifications.
     - `EXPECT_TRUE(var_f32_import->copy()->same(var_f32_import.get()))`:  This line tests the cloning functionality of globals.
     - *Key Insight:* This section tests the core functionality of global variables: initial values, read access, and write access (for mutable globals).

4. **Address the Specific Questions:** Now that the code's functionality is understood, systematically answer the prompt's questions:

   - **Functionality:** Summarize the purpose of the code based on the breakdown above.
   - **Torque:**  Check the file extension. Since it's `.cc`, it's C++, not Torque. Explain the difference.
   - **JavaScript Relation:**  Connect the C++ code to its JavaScript equivalent.
     - Explain how JavaScript can import and export WebAssembly globals.
     - Provide a JavaScript code example demonstrating importing, accessing, and modifying globals. This is a crucial part of understanding how this C++ test relates to the user-facing API.
   - **Code Logic Inference (Input/Output):** Choose a specific scenario (e.g., setting an imported variable). Define the "input" (the value being set) and the "output" (the value obtained by reading the variable). This helps illustrate the effect of the code.
   - **Common Programming Errors:** Think about typical mistakes when working with WebAssembly globals in JavaScript:
     - Trying to set immutable globals.
     - Incorrectly assuming the initial value if not explicitly provided.
     - Type mismatches.
     - Explain these errors and provide JavaScript examples.

5. **Refine and Organize:**  Structure the explanation logically with clear headings and bullet points. Use precise language. Double-check the code and the generated explanation for accuracy and completeness. Ensure the JavaScript examples are correct and easy to understand.

**(Self-Correction Example During the Process):**  Initially, I might have just said "it tests global variables."  But after closer inspection, I realized it's testing *both* imported and exported globals, with different mutability and data types. This level of detail is important for a comprehensive explanation. Similarly, when explaining the JavaScript relation, simply stating "JavaScript can interact with globals" is insufficient. Providing a concrete example makes the connection much clearer.
看起来 `v8/test/wasm-api-tests/globals.cc` 是一个 C++ 源代码文件，用于测试 V8 JavaScript 引擎中 WebAssembly API 关于全局变量的功能。

**它的主要功能可以概括为:**

1. **定义和实例化带有导入和导出全局变量的 WebAssembly 模块。**  该测试创建了一个 WebAssembly 模块，其中包含：
    * **导入的全局变量:**  这些全局变量在 WebAssembly 模块外部定义，并通过导入声明引入。测试中定义了四种导入的全局变量，分别具有不同的类型（f32, i64）和可变性（const, var）。
    * **导出的全局变量:** 这些全局变量在 WebAssembly 模块内部定义并通过导出声明使其可以从外部访问。测试中也定义了四种导出的全局变量，具有不同的类型和可变性，并使用 `WasmInitExpr` 提供了初始值。

2. **定义用于访问和修改全局变量的 WebAssembly 函数。** 该测试还定义了一些导出的 WebAssembly 函数，用于：
    * **获取（读取）全局变量的值：**  针对每种类型的导入和导出全局变量（const f32, const i64, var f32, var i64）都定义了相应的获取函数。
    * **设置（写入）可变全局变量的值：** 针对每种类型的可变导入和导出全局变量（var f32, var i64）都定义了相应的设置函数。

3. **在 C++ 测试代码中创建和配置导入的全局变量实例。**  测试代码使用 V8 的 C++ API 创建 `Global` 对象，这些对象代表了导入的全局变量的实际实例，并为它们设置了初始值。

4. **实例化 WebAssembly 模块，并将导入的全局变量实例传递给它。**  `Instantiate(imports)` 这行代码将之前创建的导入全局变量连接到 WebAssembly 模块。

5. **提取导出的全局变量和函数。**  测试代码通过 V8 的 API 获取对 WebAssembly 模块中导出的全局变量和函数的引用。

6. **通过 C++ API 和导出的函数验证全局变量的行为。** 测试代码执行以下操作来验证全局变量的功能：
    * **检查初始值：**  验证导入和导出全局变量的初始值是否与预期一致。
    * **修改可变全局变量的值：**  使用 C++ API 的 `set` 方法和导出的设置函数来修改可变全局变量的值。
    * **读取全局变量的值：**  使用 C++ API 的 `get` 方法和导出的获取函数来读取全局变量的值，并验证修改是否生效。
    * **测试克隆：**  测试可变全局变量的克隆功能。

**关于文件后缀名和 Torque:**

该文件名为 `globals.cc`，以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**。 如果文件以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。 Torque 是一种用于定义 V8 内部函数的领域特定语言。

**与 JavaScript 的功能关系以及 JavaScript 示例:**

该 C++ 测试文件验证了 WebAssembly 的全局变量功能，这些功能可以通过 JavaScript API 进行交互。  在 JavaScript 中，你可以创建、导入、导出和操作 WebAssembly 模块的全局变量。

**JavaScript 示例:**

```javascript
// 假设你已经编译了一个包含导入和导出全局变量的 WebAssembly 模块到 'globals.wasm'

async function runWasm() {
  const response = await fetch('globals.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);

  // 定义导入的全局变量
  const importObject = {
    env: {
      'const f32': new WebAssembly.Global({ value: 'f32', mutable: false }, 1.0),
      'const i64': new WebAssembly.Global({ value: 'i64', mutable: false }, 2n),
      'var f32': new WebAssembly.Global({ value: 'f32', mutable: true }, 3.0),
      'var i64': new WebAssembly.Global({ value: 'i64', mutable: true }, 4n),
    },
  };

  const instance = await WebAssembly.instantiate(module, importObject);

  // 访问导出的全局变量
  console.log("Initial exported const f32:", instance.exports['const f32'].value);
  console.log("Initial exported const i64:", instance.exports['const i64'].value);
  console.log("Initial exported var f32:", instance.exports['var f32'].value);
  console.log("Initial exported var i64:", instance.exports['var i64'].value);

  // 调用导出的函数获取全局变量的值
  console.log("Get const f32 import via function:", instance.exports['get const f32 import']());
  console.log("Get const i64 import via function:", instance.exports['get const i64 import']());
  console.log("Get var f32 import via function:", instance.exports['get var f32 import']());
  console.log("Get var i64 import via function:", instance.exports['get var i64 import']());
  console.log("Get const f32 export via function:", instance.exports['get const f32 export']());
  console.log("Get const i64 export via function:", instance.exports['get const i64 export']());
  console.log("Get var f32 export via function:", instance.exports['get var f32 export']());
  console.log("Get var i64 export via function:", instance.exports['get var i64 export']());

  // 修改导出的可变全局变量
  instance.exports['var f32'].value = 35.0;
  instance.exports['var i64'].value = 36n;
  console.log("Modified exported var f32:", instance.exports['var f32'].value);
  console.log("Modified exported var i64:", instance.exports['var i64'].value);

  // 调用导出的函数修改导入和导出的可变全局变量
  instance.exports['set var f32 import'](73.0);
  instance.exports['set var i64 import'](74n);
  instance.exports['set var f32 export'](75.0);
  instance.exports['set var i64 export'](76n);

  console.log("Modified imported var f32 via function:", instance.exports['get var f32 import']());
  console.log("Modified imported var i64 via function:", instance.exports['get var i64 import']());
  console.log("Modified exported var f32 via function:", instance.exports['get var f32 export']());
  console.log("Modified exported var i64 via function:", instance.exports['get var i64 export']());
}

runWasm();
```

**代码逻辑推理 (假设输入与输出):**

**场景:** 调用 WebAssembly 导出的函数 `get var f32 export`。

**假设输入:** 在实例化模块时，导出的可变全局变量 `var f32` 的初始值为 `7.0` (由 `WasmInitExpr(7.f)` 设置)。  在调用 `get var f32 export` 之前，没有通过其他方式修改过该全局变量的值。

**代码逻辑:** `get var f32 export` 函数的 WebAssembly 代码是 `WASM_GLOBAL_GET(vfe_index)`，它会获取索引为 `vfe_index` 的全局变量的值，并将其作为函数的返回值。`vfe_index` 对应于导出的可变 `f32` 全局变量。

**预期输出:** 函数 `get var f32 export` 将返回浮点数 `7.0`。

**场景:** 调用 WebAssembly 导出的函数 `set var i64 import` 并传入参数 `100n`。

**假设输入:** 在调用 `set var i64 import` 之前，导入的可变全局变量 `var i64` 的值为 `4n` (在 C++ 代码中创建 `Global` 对象时设置)。

**代码逻辑:** `set var i64 import` 函数的 WebAssembly 代码是 `WASM_GLOBAL_SET(vii_index, WASM_LOCAL_GET(0))`。它会将函数的第一个局部变量（即传入的参数）的值设置到索引为 `vii_index` 的全局变量中。`vii_index` 对应于导入的可变 `i64` 全局变量。

**预期输出:** 在调用 `set var i64 import(100n)` 后，导入的全局变量 `var i64` 的值将变为 `100n`。

**用户常见的编程错误示例 (JavaScript):**

1. **尝试修改不可变的全局变量:**

   ```javascript
   // 假设 instance.exports['const f32'] 是一个不可变的导出的全局变量
   try {
     instance.exports['const f32'].value = 10.0; // 错误！
   } catch (e) {
     console.error("Error setting immutable global:", e); // 将抛出一个 TypeError
   }
   ```
   **解释:**  用户试图修改一个被声明为不可变的全局变量，这在 WebAssembly 规范中是不允许的，会抛出 `TypeError`。

2. **在导入时类型不匹配:**

   ```javascript
   // WebAssembly 模块期望导入一个 f32 类型的全局变量 'my_f32_import'
   const importObject = {
     env: {
       'my_f32_import': new WebAssembly.Global({ value: 'i32', mutable: false }, 10), // 错误！类型不匹配
     },
   };

   // 尝试实例化模块将会失败或者导致未定义的行为
   ```
   **解释:**  导入的 JavaScript 全局变量的类型（`i32`）与 WebAssembly 模块期望的类型（`f32`）不匹配。这会导致实例化失败或运行时错误。

3. **忘记设置导入的全局变量的初始值:**

   ```javascript
   // WebAssembly 模块导入一个 i64 类型的全局变量 'my_i64_import'
   const importObject = {
     env: {
       'my_i64_import': new WebAssembly.Global({ value: 'i64', mutable: true }), // 警告：没有提供初始值
     },
   };

   // 全局变量的初始值将是其类型的默认值（例如，i64 的默认值为 0n）
   const instance = await WebAssembly.instantiate(module, importObject);
   console.log(instance.exports['get_imported_i64']()); // 可能会输出 0n，而不是预期的值
   ```
   **解释:**  虽然不一定会报错，但如果没有为导入的全局变量提供初始值，它将使用该类型的默认值，这可能不是用户期望的行为。

4. **假设导出的全局变量总是存在:**

   ```javascript
   // 假设 WebAssembly 模块的导出部分可能因为构建配置或其他原因而有所不同
   const instance = await WebAssembly.instantiate(module);
   if (instance.exports['my_exported_global']) {
     console.log(instance.exports['my_exported_global'].value);
   } else {
     console.log("Exported global 'my_exported_global' not found.");
   }
   ```
   **解释:**  在访问导出的全局变量之前，应该检查它是否存在于 `instance.exports` 对象中，以避免访问未定义属性的错误。

总而言之，`v8/test/wasm-api-tests/globals.cc` 是一个重要的测试文件，它通过 C++ 代码详细地测试了 V8 引擎中 WebAssembly 全局变量的各种功能，包括导入、导出、可变性、初始值以及通过函数进行访问和修改。这有助于确保 JavaScript API 中与 WebAssembly 全局变量相关的行为符合预期。

Prompt: 
```
这是目录为v8/test/wasm-api-tests/globals.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/wasm-api-tests/globals.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/wasm-api-tests/wasm-api-test.h"

namespace v8 {
namespace internal {
namespace wasm {

using ::wasm::GlobalType;

TEST_F(WasmCapiTest, Globals) {
  const bool kMutable = true;
  const bool kImmutable = false;

  // Define imported and exported globals in the module.
  const uint32_t cfi_index = builder()->AddGlobalImport(
      base::CStrVector("const f32"), kWasmF32, kImmutable);
  const uint32_t cii_index = builder()->AddGlobalImport(
      base::CStrVector("const i64"), kWasmI64, kImmutable);
  const uint32_t vfi_index = builder()->AddGlobalImport(
      base::CStrVector("var f32"), kWasmF32, kMutable);
  const uint32_t vii_index = builder()->AddGlobalImport(
      base::CStrVector("var i64"), kWasmI64, kMutable);
  const int kNumImported = 4;

  const uint32_t cfe_index =
      kNumImported +
      builder()->AddExportedGlobal(kWasmF32, kImmutable, WasmInitExpr(5.f),
                                   base::CStrVector("const f32"));
  const uint32_t cie_index =
      kNumImported + builder()->AddExportedGlobal(
                         kWasmI64, kImmutable, WasmInitExpr(int64_t{6}),
                         base::CStrVector("const i64"));
  const uint32_t vfe_index =
      kNumImported + builder()->AddExportedGlobal(kWasmF32, kMutable,
                                                  WasmInitExpr(7.f),
                                                  base::CStrVector("var f32"));
  const uint32_t vie_index =
      kNumImported + builder()->AddExportedGlobal(kWasmI64, kMutable,
                                                  WasmInitExpr(int64_t{8}),
                                                  base::CStrVector("var i64"));

  // Define functions for inspecting globals.
  ValueType f32_type[] = {kWasmF32};
  ValueType i64_type[] = {kWasmI64};
  FunctionSig return_f32(1, 0, f32_type);
  FunctionSig return_i64(1, 0, i64_type);
  uint8_t gcfi[] = {WASM_GLOBAL_GET(cfi_index)};
  AddExportedFunction(base::CStrVector("get const f32 import"), gcfi,
                      sizeof(gcfi), &return_f32);
  uint8_t gcii[] = {WASM_GLOBAL_GET(cii_index)};
  AddExportedFunction(base::CStrVector("get const i64 import"), gcii,
                      sizeof(gcii), &return_i64);
  uint8_t gvfi[] = {WASM_GLOBAL_GET(vfi_index)};
  AddExportedFunction(base::CStrVector("get var f32 import"), gvfi,
                      sizeof(gvfi), &return_f32);
  uint8_t gvii[] = {WASM_GLOBAL_GET(vii_index)};
  AddExportedFunction(base::CStrVector("get var i64 import"), gvii,
                      sizeof(gvii), &return_i64);

  uint8_t gcfe[] = {WASM_GLOBAL_GET(cfe_index)};
  AddExportedFunction(base::CStrVector("get const f32 export"), gcfe,
                      sizeof(gcfe), &return_f32);
  uint8_t gcie[] = {WASM_GLOBAL_GET(cie_index)};
  AddExportedFunction(base::CStrVector("get const i64 export"), gcie,
                      sizeof(gcie), &return_i64);
  uint8_t gvfe[] = {WASM_GLOBAL_GET(vfe_index)};
  AddExportedFunction(base::CStrVector("get var f32 export"), gvfe,
                      sizeof(gvfe), &return_f32);
  uint8_t gvie[] = {WASM_GLOBAL_GET(vie_index)};
  AddExportedFunction(base::CStrVector("get var i64 export"), gvie,
                      sizeof(gvie), &return_i64);

  // Define functions for manipulating globals.
  FunctionSig param_f32(0, 1, f32_type);
  FunctionSig param_i64(0, 1, i64_type);
  uint8_t svfi[] = {WASM_GLOBAL_SET(vfi_index, WASM_LOCAL_GET(0))};
  AddExportedFunction(base::CStrVector("set var f32 import"), svfi,
                      sizeof(svfi), &param_f32);
  uint8_t svii[] = {WASM_GLOBAL_SET(vii_index, WASM_LOCAL_GET(0))};
  AddExportedFunction(base::CStrVector("set var i64 import"), svii,
                      sizeof(svii), &param_i64);
  uint8_t svfe[] = {WASM_GLOBAL_SET(vfe_index, WASM_LOCAL_GET(0))};
  AddExportedFunction(base::CStrVector("set var f32 export"), svfe,
                      sizeof(svfe), &param_f32);
  uint8_t svie[] = {WASM_GLOBAL_SET(vie_index, WASM_LOCAL_GET(0))};
  AddExportedFunction(base::CStrVector("set var i64 export"), svie,
                      sizeof(svie), &param_i64);

  // Create imported globals.
  own<GlobalType> const_f32_type =
      GlobalType::make(ValType::make(::wasm::F32), ::wasm::CONST);
  own<GlobalType> const_i64_type =
      GlobalType::make(ValType::make(::wasm::I64), ::wasm::CONST);
  own<GlobalType> var_f32_type =
      GlobalType::make(ValType::make(::wasm::F32), ::wasm::VAR);
  own<GlobalType> var_i64_type =
      GlobalType::make(ValType::make(::wasm::I64), ::wasm::VAR);
  own<Global> const_f32_import =
      Global::make(store(), const_f32_type.get(), Val::f32(1));
  own<Global> const_i64_import =
      Global::make(store(), const_i64_type.get(), Val::i64(2));
  own<Global> var_f32_import =
      Global::make(store(), var_f32_type.get(), Val::f32(3));
  own<Global> var_i64_import =
      Global::make(store(), var_i64_type.get(), Val::i64(4));
  Extern* imports[] = {const_f32_import.get(), const_i64_import.get(),
                       var_f32_import.get(), var_i64_import.get()};

  Instantiate(imports);

  // Extract exports.
  size_t i = 0;
  Global* const_f32_export = GetExportedGlobal(i++);
  Global* const_i64_export = GetExportedGlobal(i++);
  Global* var_f32_export = GetExportedGlobal(i++);
  Global* var_i64_export = GetExportedGlobal(i++);
  Func* get_const_f32_import = GetExportedFunction(i++);
  Func* get_const_i64_import = GetExportedFunction(i++);
  Func* get_var_f32_import = GetExportedFunction(i++);
  Func* get_var_i64_import = GetExportedFunction(i++);
  Func* get_const_f32_export = GetExportedFunction(i++);
  Func* get_const_i64_export = GetExportedFunction(i++);
  Func* get_var_f32_export = GetExportedFunction(i++);
  Func* get_var_i64_export = GetExportedFunction(i++);
  Func* set_var_f32_import = GetExportedFunction(i++);
  Func* set_var_i64_import = GetExportedFunction(i++);
  Func* set_var_f32_export = GetExportedFunction(i++);
  Func* set_var_i64_export = GetExportedFunction(i++);

  // Try cloning.
  EXPECT_TRUE(var_f32_import->copy()->same(var_f32_import.get()));

  // Check initial values.
  EXPECT_EQ(1.f, const_f32_import->get().f32());
  EXPECT_EQ(2, const_i64_import->get().i64());
  EXPECT_EQ(3.f, var_f32_import->get().f32());
  EXPECT_EQ(4, var_i64_import->get().i64());
  EXPECT_EQ(5.f, const_f32_export->get().f32());
  EXPECT_EQ(6, const_i64_export->get().i64());
  EXPECT_EQ(7.f, var_f32_export->get().f32());
  EXPECT_EQ(8, var_i64_export->get().i64());
  Val result[1];
  get_const_f32_import->call(nullptr, result);
  EXPECT_EQ(1.f, result[0].f32());
  get_const_i64_import->call(nullptr, result);
  EXPECT_EQ(2, result[0].i64());
  get_var_f32_import->call(nullptr, result);
  EXPECT_EQ(3.f, result[0].f32());
  get_var_i64_import->call(nullptr, result);
  EXPECT_EQ(4, result[0].i64());
  get_const_f32_export->call(nullptr, result);
  EXPECT_EQ(5.f, result[0].f32());
  get_const_i64_export->call(nullptr, result);
  EXPECT_EQ(6, result[0].i64());
  get_var_f32_export->call(nullptr, result);
  EXPECT_EQ(7.f, result[0].f32());
  get_var_i64_export->call(nullptr, result);
  EXPECT_EQ(8, result[0].i64());

  // Modify variables through the API and check again.
  var_f32_import->set(Val::f32(33));
  var_i64_import->set(Val::i64(34));
  var_f32_export->set(Val::f32(35));
  var_i64_export->set(Val::i64(36));

  EXPECT_EQ(33.f, var_f32_import->get().f32());
  EXPECT_EQ(34, var_i64_import->get().i64());
  EXPECT_EQ(35.f, var_f32_export->get().f32());
  EXPECT_EQ(36, var_i64_export->get().i64());

  get_var_f32_import->call(nullptr, result);
  EXPECT_EQ(33.f, result[0].f32());
  get_var_i64_import->call(nullptr, result);
  EXPECT_EQ(34, result[0].i64());
  get_var_f32_export->call(nullptr, result);
  EXPECT_EQ(35.f, result[0].f32());
  get_var_i64_export->call(nullptr, result);
  EXPECT_EQ(36, result[0].i64());

  // Modify variables through calls and check again.
  Val args[1];
  args[0] = Val::f32(73);
  set_var_f32_import->call(args, nullptr);
  args[0] = Val::i64(74);
  set_var_i64_import->call(args, nullptr);
  args[0] = Val::f32(75);
  set_var_f32_export->call(args, nullptr);
  args[0] = Val::i64(76);
  set_var_i64_export->call(args, nullptr);

  EXPECT_EQ(73.f, var_f32_import->get().f32());
  EXPECT_EQ(74, var_i64_import->get().i64());
  EXPECT_EQ(75.f, var_f32_export->get().f32());
  EXPECT_EQ(76, var_i64_export->get().i64());

  get_var_f32_import->call(nullptr, result);
  EXPECT_EQ(73.f, result[0].f32());
  get_var_i64_import->call(nullptr, result);
  EXPECT_EQ(74, result[0].i64());
  get_var_f32_export->call(nullptr, result);
  EXPECT_EQ(75.f, result[0].f32());
  get_var_i64_export->call(nullptr, result);
  EXPECT_EQ(76, result[0].i64());
}

}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```