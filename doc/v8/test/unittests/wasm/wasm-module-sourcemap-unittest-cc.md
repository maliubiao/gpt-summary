Response:
Let's break down the thought process to analyze the C++ code and fulfill the request.

1. **Understand the Goal:** The primary goal is to understand the functionality of the given C++ code related to WASM source maps in the V8 engine. The request also includes specific instructions about how to present the findings (listing functionalities, relating to JavaScript, showing logic, and highlighting common errors).

2. **Initial Scan and Keyword Recognition:** I first scan the code for recognizable keywords and patterns. Key things I notice are:
    * `#include "src/wasm/wasm-module-sourcemap.h"`:  This immediately tells me the code is directly related to WASM source map handling.
    * `namespace v8`, `namespace internal`, `namespace wasm`: This indicates it's part of the V8 engine's internal WASM implementation.
    * `class WasmModuleSourceMapTest : public TestWithIsolateAndZone`: This strongly suggests it's a unit test file. The `TEST_F` macros confirm this.
    * `EXPECT_FALSE`, `EXPECT_TRUE`, `EXPECT_STREQ`, `EXPECT_EQ`: These are Google Test assertion macros, further reinforcing the unit test nature.
    * String literals like `"{\"version\":3,..."`: These look like JSON strings representing source map data.
    * Function names like `IsValid`, `HasSource`, `HasValidEntry`, `GetFilename`, `GetSourceLine`: These are likely methods of the `WasmModuleSourceMap` class being tested.

3. **Deduce Core Functionality:** Based on the keywords and the structure of the tests, I can infer the main functionalities being tested:
    * **Parsing and Validation of Source Maps:** The `InvalidSourceMap` test case clearly focuses on checking if the `WasmModuleSourceMap` class correctly identifies invalid source map JSON. It tests various error conditions (missing fields, wrong types, incorrect values).
    * **Mapping WASM Bytecode Offsets to Source Locations:** The other test cases (`HasSource`, `HasValidEntry`, `GetFilename`, `SourceLine`) all use a valid source map and then call methods of `WasmModuleSourceMap` with numerical arguments (likely WASM bytecode offsets). The assertions then check the results, suggesting these methods are responsible for looking up source information based on these offsets.

4. **Relate to JavaScript (If Applicable):**  The request specifically asks to relate the functionality to JavaScript. WASM itself is often a compilation target for languages like C++ or Rust, but it's *run* within a JavaScript environment (like a browser or Node.js). Source maps are crucial for debugging WASM modules from the original source code within the JavaScript developer tools. So, the connection is about **debugging experience**. When an error occurs in a WASM module, the source map allows the browser's debugger to show the error in the original C++ or Rust code, not just the raw WASM bytecode.

5. **Illustrate with JavaScript (If Applicable):**  To provide a concrete JavaScript example, I would imagine a simple scenario: a JavaScript application loads a WASM module, calls a function in it, and an error occurs. The browser, using the source map, would pinpoint the error in the original source file. A simplified code snippet demonstrates this loading and calling process.

6. **Logic and Assumptions (Input/Output):** For the code logic reasoning, I focus on the individual test cases. Each test case sets up a specific source map and then calls methods with specific byte offsets. I identify the *input* as the bytecode offset(s) and the *output* as the boolean (for `HasSource`, `HasValidEntry`), filename string (for `GetFilename`), or line number (for `SourceLine`). I examine the assertions to understand the expected output for the given inputs.

7. **Common Programming Errors:** The `InvalidSourceMap` test case is a goldmine for identifying common errors when *generating* source maps. These are errors a tool that produces WASM and its source map might make. I extract these directly from the test case:
    * Missing "sources" array
    * Misspelling "mappings"
    * Using the wrong "version" number
    * Providing the wrong data type for "version" or "sources".
    * Having invalid characters in the "mappings" string.

8. **Structure the Answer:** Finally, I organize the findings according to the instructions in the request:
    * List the functionalities clearly.
    * Explain the relationship to JavaScript with an example.
    * Provide input/output examples based on the test cases.
    * List common programming errors illustrated by the tests.

9. **Review and Refine:** I reread my answer and compare it to the original code and the request to ensure accuracy, clarity, and completeness. I check for any misinterpretations or omissions. For example, I initially might not have explicitly stated that the byte offsets refer to the WASM bytecode, but during review, I'd realize this is a crucial detail to include.

This iterative process of scanning, deducing, relating, illustrating, and structuring allows me to effectively analyze the code and provide a comprehensive answer that addresses all aspects of the request.
这个 C++ 代码文件 `v8/test/unittests/wasm/wasm-module-sourcemap-unittest.cc` 是 V8 JavaScript 引擎中 **WebAssembly (Wasm) 模块的源代码映射 (sourcemap) 功能的单元测试文件**。

以下是它的主要功能点的详细说明：

**1. 测试 `WasmModuleSourceMap` 类的功能:**

   - 该文件通过使用 Google Test 框架定义了一系列测试用例（以 `TEST_F` 开头），来验证 `WasmModuleSourceMap` 类的各种方法是否按预期工作。
   - `WasmModuleSourceMap` 类负责解析和使用 Wasm 模块的源代码映射信息。源代码映射用于将 Wasm 字节码的偏移量映射回原始源代码的位置（例如，文件名和行号）。这在调试 Wasm 模块时非常有用。

**2. 验证无效的源代码映射:**

   - `TEST_F(WasmModuleSourceMapTest, InvalidSourceMap)` 测试用例专门用于检查 `WasmModuleSourceMap` 类是否能正确识别和处理各种格式错误的源代码映射 JSON 字符串。
   - 它测试了以下几种无效情况：
     - 缺少 "sources" 字段。
     - 错误的键名（例如，将 "mappings" 拼写成 "mapping"）。
     - 错误的 "version" 值（应该为 3）。
     - "version" 字段不是数字类型。
     - "sources" 字段不是数组类型。
     - "mappings" 字段包含无效的字符。
   - 对于每种无效情况，它都创建了一个 `WasmModuleSourceMap` 对象，并使用 `EXPECT_FALSE(ptr->IsValid())` 断言该源代码映射被认为是无效的。

**3. 测试 `HasSource` 方法:**

   - `TEST_F(WasmModuleSourceMapTest, HasSource)` 测试用例使用一个有效的源代码映射，并测试 `HasSource(uint32_t start, uint32_t end)` 方法。
   - `HasSource` 方法用于检查在给定的 Wasm 字节码偏移量范围内是否存在与源代码相关的映射信息。
   - 测试用例中，它针对不同的偏移量范围调用 `HasSource`，并使用 `EXPECT_TRUE` 和 `EXPECT_FALSE` 来断言是否找到了对应的源信息。

**4. 测试 `HasValidEntry` 方法:**

   - `TEST_F(WasmModuleSourceMapTest, HasValidEntry)` 测试用例测试 `HasValidEntry(uint32_t start, uint32_t end)` 方法。
   - `HasValidEntry` 方法与 `HasSource` 类似，也检查给定偏移量范围内是否存在源代码映射，但可能在内部实现上有一些细微的区别。

**5. 测试 `GetFilename` 方法:**

   - `TEST_F(WasmModuleSourceMapTest, GetFilename)` 测试用例测试 `GetFilename(uint32_t offset)` 方法。
   - `GetFilename` 方法返回给定 Wasm 字节码偏移量对应的源文件名。
   - 测试用例使用 `EXPECT_STREQ` 来断言返回的文件名是否与预期的文件名字符串匹配。

**6. 测试 `SourceLine` 方法:**

   - `TEST_F(WasmModuleSourceMapTest, SourceLine)` 测试用例测试 `GetSourceLine(uint32_t offset)` 方法。
   - `GetSourceLine` 方法返回给定 Wasm 字节码偏移量对应的源代码行号。
   - 测试用例使用 `EXPECT_EQ` 来断言返回的行号是否与预期的行号匹配。

**如果 `v8/test/unittests/wasm/wasm-module-sourcemap-unittest.cc` 以 `.tq` 结尾:**

   - 那么它将是一个 **V8 Torque 源代码文件**。 Torque 是 V8 用来编写其内部代码（例如，内置函数和类型系统）的一种领域特定语言。
   - 由于当前的文件名是 `.cc`，它是一个 C++ 文件。

**与 JavaScript 的功能关系及示例:**

   - Wasm 模块通常由 JavaScript 代码加载和执行。当 Wasm 模块在运行时发生错误或需要调试时，源代码映射就发挥了关键作用。
   - 当开发者在浏览器或其他 JavaScript 运行时环境中调试 Wasm 模块时，浏览器会使用 Wasm 模块的源代码映射来将 Wasm 字节码的执行位置映射回原始源代码的位置。这使得开发者能够像调试 JavaScript 代码一样调试 Wasm 代码，查看原始的 C++, Rust 等源代码，设置断点，单步执行等。

**JavaScript 示例:**

```javascript
// 假设我们有一个名为 'my_module.wasm' 的 Wasm 模块，
// 并且它有一个名为 'my_module.wasm.map' 的关联源代码映射文件。

async function loadAndRunWasm() {
  try {
    const response = await fetch('my_module.wasm');
    const buffer = await response.arrayBuffer();
    const module = await WebAssembly.compile(buffer);

    // 假设 Wasm 模块导出一个名为 'add' 的函数
    const instance = await WebAssembly.instantiate(module);
    const result = instance.exports.add(5, 10);
    console.log('Wasm result:', result);

  } catch (error) {
    console.error('Error loading or running Wasm module:', error);
    // 如果发生错误，并且提供了源代码映射，浏览器开发者工具
    // 可能会显示错误发生在原始的 C++/Rust 代码中，而不是 Wasm 字节码。
  }
}

loadAndRunWasm();
```

**代码逻辑推理 (假设输入与输出):**

假设 `src_map_ptr` 是通过解析以下源代码映射创建的：

```json
{
  "version": 3,
  "sources": ["./my_source.cpp"],
  "names": [],
  "mappings": "AAAA,CAAC,EAAE,CAAC,IAAI"
}
```

并且我们有一个简单的 Wasm 函数，其字节码偏移量 `0` 到 `4` 对应于源代码的某个部分。

**假设输入:**

- `src_map_ptr`: 指向解析后的 `WasmModuleSourceMap` 对象。
- `offset` (对于 `GetFilename` 和 `SourceLine`): 例如 `2`。
- `start`, `end` (对于 `HasSource` 和 `HasValidEntry`): 例如 `0`, `4`。

**预期输出:**

- `src_map_ptr->HasSource(0, 4)`: `true` (因为偏移量 0 到 4 之间存在映射)
- `src_map_ptr->HasValidEntry(0, 4)`: `true` (原因同上)
- `src_map_ptr->GetFilename(2)`: `"./my_source.cpp"`
- `src_map_ptr->GetSourceLine(2)`:  这需要根据 `mappings` 字段的具体解码结果来确定。在这个简化的例子中，假设它映射到源代码的第 1 行，那么输出将是 `1`。

**涉及用户常见的编程错误:**

该测试文件主要关注的是 V8 引擎内部对源代码映射的处理，而不是用户编写 Wasm 或 JavaScript 代码时容易犯的错误。但是，从 `InvalidSourceMap` 测试用例中，我们可以推断出 **生成源代码映射的工具** 可能会犯以下错误：

1. **忘记包含必要的字段:** 例如，缺少 "sources" 字段。这会导致调试器无法找到原始源文件。
   ```json
   // 错误：缺少 "sources" 字段
   {
     "version": 3,
     "names": [],
     "mappings": "..."
   }
   ```

2. **拼写错误的字段名称:** 例如，将 "mappings" 误写为 "mapping"。这会导致解析器无法识别该字段。
   ```json
   // 错误：拼写错误 "mappings"
   {
     "version": 3,
     "sources": ["source.cpp"],
     "names": [],
     "mapping": "..."
   }
   ```

3. **使用错误的 "version" 值:** 源代码映射规范指定了版本号，通常是 3。使用错误的版本号可能导致不兼容。
   ```json
   // 错误：错误的 "version"
   {
     "version": 2,
     "sources": ["source.cpp"],
     "names": [],
     "mappings": "..."
   }
   ```

4. **使用错误的数据类型:** 例如，将 "version" 或 "sources" 字段设置为错误的类型（例如，数字数组而不是数字，字符串而不是字符串数组）。
   ```json
   // 错误："version" 是数组
   {
     "version": [3],
     "sources": ["source.cpp"],
     "names": [],
     "mappings": "..."
   }

   // 错误："sources" 是字符串
   {
     "version": 3,
     "sources": "source.cpp",
     "names": [],
     "mappings": "..."
   }
   ```

5. **在 "mappings" 字段中使用无效字符:** "mappings" 字段是一个 Base64 VLQ 编码的字符串，如果包含无效字符，则无法正确解码。
   ```json
   // 错误："mappings" 包含无效字符 "&"
   {
     "version": 3,
     "sources": ["source.cpp"],
     "names": [],
     "mappings": "&..."
   }
   ```

总而言之，`v8/test/unittests/wasm/wasm-module-sourcemap-unittest.cc` 是 V8 引擎中用于测试 Wasm 模块源代码映射功能的核心单元测试文件，它验证了源代码映射的解析、有效性检查以及将 Wasm 字节码偏移量映射回源代码位置的能力。这对于在 JavaScript 环境中调试 Wasm 模块至关重要。

### 提示词
```
这是目录为v8/test/unittests/wasm/wasm-module-sourcemap-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/wasm-module-sourcemap-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/wasm-module-sourcemap.h"
#include <memory>

#include "src/api/api.h"
#include "test/common/wasm/flag-utils.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"
#include "test/unittests/test-utils.h"
#include "testing/gmock-support.h"

namespace v8 {
namespace internal {
namespace wasm {

class WasmModuleSourceMapTest : public TestWithIsolateAndZone {};

TEST_F(WasmModuleSourceMapTest, InvalidSourceMap) {
  auto i_isolate = isolate();
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(i_isolate);

  // Incomplete source map without "sources" entry.
  char incomplete_src_map[] =
      "{\"version\":3,\"names\":[],\"mappings\":\"6/"
      "BAGA,0DAIA,2DAIA,IAEA,+BACA,wCADA,mBAGA,4CCXA,6BACA,IACA,4BACA,gBADA,"
      "mBAIA,4BACA,QADA,mBAIA,4BACA,gBADA,mBAVA,mBAcA\"}";
  auto incomplete_src_map_str =
      v8::String::NewFromUtf8(v8_isolate, incomplete_src_map).ToLocalChecked();
  std::unique_ptr<WasmModuleSourceMap> incomplete_src_map_ptr(
      new WasmModuleSourceMap(v8_isolate, incomplete_src_map_str));
  EXPECT_FALSE(incomplete_src_map_ptr->IsValid());

  // Miswrite key "mappings" as "mapping".
  char wrong_key[] =
      "{\"version\":3,\"sources\":[\"./"
      "test.h\",\"main.cpp\"],\"names\":[],\"mapping\":\"6/"
      "BAGA,0DAIA,2DAIA,IAEA,+BACA,wCADA,mBAGA,4CCXA,6BACA,IACA,4BACA,gBADA,"
      "mBAIA,4BACA,QADA,mBAIA,4BACA,gBADA,mBAVA,mBAcA\"}";
  auto wrong_key_str =
      v8::String::NewFromUtf8(v8_isolate, wrong_key).ToLocalChecked();
  std::unique_ptr<WasmModuleSourceMap> wrong_key_ptr(
      new WasmModuleSourceMap(v8_isolate, wrong_key_str));
  EXPECT_FALSE(wrong_key_ptr->IsValid());

  // Wrong version number.
  char wrong_ver[] =
      "{\"version\":2,\"sources\":[\"./"
      "test.h\",\"main.cpp\"],\"names\":[],\"mappings\":\"6/"
      "BAGA,0DAIA,2DAIA,IAEA,+BACA,wCADA,mBAGA,4CCXA,6BACA,IACA,4BACA,gBADA,"
      "mBAIA,4BACA,QADA,mBAIA,4BACA,gBADA,mBAVA,mBAcA\"}";
  auto wrong_ver_str =
      v8::String::NewFromUtf8(v8_isolate, wrong_ver).ToLocalChecked();
  std::unique_ptr<WasmModuleSourceMap> wrong_ver_ptr(
      new WasmModuleSourceMap(v8_isolate, wrong_ver_str));
  EXPECT_FALSE(wrong_ver_ptr->IsValid());

  // Wrong type of "version" entry.
  char ver_as_arr[] =
      "{\"version\":[3],\"sources\":[\"./"
      "test.h\",\"main.cpp\"],\"names\":[],\"mappings\":\"6/"
      "BAGA,0DAIA,2DAIA,IAEA,+BACA,wCADA,mBAGA,4CCXA,6BACA,IACA,4BACA,gBADA,"
      "mBAIA,4BACA,QADA,mBAIA,4BACA,gBADA,mBAVA,mBAcA\"}";
  auto ver_as_arr_str =
      v8::String::NewFromUtf8(v8_isolate, ver_as_arr).ToLocalChecked();
  std::unique_ptr<WasmModuleSourceMap> ver_as_arr_ptr(
      new WasmModuleSourceMap(v8_isolate, ver_as_arr_str));
  EXPECT_FALSE(ver_as_arr_ptr->IsValid());

  // Wrong type of "sources" entry.
  char sources_as_str[] =
      "{\"version\":3,\"sources\":\"./"
      "test.h,main.cpp\",\"names\":[],\"mappings\":\"6/"
      "BAGA,0DAIA,2DAIA,IAEA,+BACA,wCADA,mBAGA,4CCXA,6BACA,IACA,4BACA,gBADA,"
      "mBAIA,4BACA,QADA,mBAIA,4BACA,gBADA,mBAVA,mBAcA\"}";
  auto sources_as_str_str =
      v8::String::NewFromUtf8(v8_isolate, sources_as_str).ToLocalChecked();
  std::unique_ptr<WasmModuleSourceMap> sources_as_str_ptr(
      new WasmModuleSourceMap(v8_isolate, sources_as_str_str));
  EXPECT_FALSE(sources_as_str_ptr->IsValid());

  // Invalid "mappings" entry.
  char wrong_mappings[] =
      "{\"version\":3,\"sources\":[\"./"
      "test.h\",\"main.cpp\"],\"names\":[],\"mappings\":\"6/"
      "&BAGA,0DAIA,2DAIA,IAEA,+BACA,wCADA,mBAGA,4CCXA,6BACA,IACA,4BACA,gBADA,"
      "mBAIA,4BACA,QADA,mBAIA,4BACA,gBADA,mBAVA,mBAcA\"}";
  auto wrong_mappings_str =
      v8::String::NewFromUtf8(v8_isolate, wrong_mappings).ToLocalChecked();
  std::unique_ptr<WasmModuleSourceMap> wrong_mappings_ptr(
      new WasmModuleSourceMap(v8_isolate, wrong_mappings_str));
  EXPECT_FALSE(wrong_mappings_ptr->IsValid());
}

TEST_F(WasmModuleSourceMapTest, HasSource) {
  char src_map[] =
      "{\"version\":3,\"sources\":[\"./"
      "test.h\",\"main.cpp\"],\"names\":[],\"mappings\":\"6/"
      "BAGA,0DAIA,2DAIA,IAEA,+BACA,wCADA,mBAGA,4CCXA,6BACA,IACA,4BACA,gBADA,"
      "mBAIA,4BACA,QADA,mBAIA,4BACA,gBADA,mBAVA,mBAcA\"}";
  auto i_isolate = isolate();
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(i_isolate);
  auto src_map_str =
      v8::String::NewFromUtf8(v8_isolate, src_map).ToLocalChecked();
  std::unique_ptr<WasmModuleSourceMap> src_map_ptr(
      new WasmModuleSourceMap(v8_isolate, src_map_str));
  EXPECT_TRUE(src_map_ptr->IsValid());

  EXPECT_FALSE(src_map_ptr->HasSource(0x387, 0x3AF));
  EXPECT_FALSE(src_map_ptr->HasSource(0x3B0, 0x3B5));
  EXPECT_FALSE(src_map_ptr->HasSource(0x3B6, 0x3BC));
  EXPECT_FALSE(src_map_ptr->HasSource(0x3BD, 0x3C7));
  EXPECT_FALSE(src_map_ptr->HasSource(0x3C8, 0x3DA));
  EXPECT_TRUE(src_map_ptr->HasSource(0x3DB, 0x414));
  EXPECT_TRUE(src_map_ptr->HasSource(0x415, 0x44E));
  EXPECT_TRUE(src_map_ptr->HasSource(0x450, 0x4DC));
  EXPECT_TRUE(src_map_ptr->HasSource(0x4DE, 0x5F1));
  EXPECT_FALSE(src_map_ptr->HasSource(0x5F3, 0x437A));
  EXPECT_FALSE(src_map_ptr->HasSource(0x437C, 0x5507));
  EXPECT_FALSE(src_map_ptr->HasSource(0x5508, 0x5557));
  EXPECT_FALSE(src_map_ptr->HasSource(0x5559, 0x5609));
  EXPECT_FALSE(src_map_ptr->HasSource(0x560A, 0x563D));
  EXPECT_FALSE(src_map_ptr->HasSource(0x563E, 0x564A));
  EXPECT_FALSE(src_map_ptr->HasSource(0x564B, 0x5656));
  EXPECT_FALSE(src_map_ptr->HasSource(0x5658, 0x5713));
  EXPECT_FALSE(src_map_ptr->HasSource(0x5715, 0x59B0));
  EXPECT_FALSE(src_map_ptr->HasSource(0x59B1, 0x59BC));
  EXPECT_FALSE(src_map_ptr->HasSource(0x59BD, 0x59C6));
  EXPECT_FALSE(src_map_ptr->HasSource(0x59C7, 0x59D8));
  EXPECT_FALSE(src_map_ptr->HasSource(0x59D9, 0x59E7));
  EXPECT_FALSE(src_map_ptr->HasSource(0x59E9, 0x5B50));
  EXPECT_FALSE(src_map_ptr->HasSource(0x5B52, 0x5C53));
  EXPECT_FALSE(src_map_ptr->HasSource(0x5C54, 0x5C57));
  EXPECT_FALSE(src_map_ptr->HasSource(0x5C59, 0x5EBD));
  EXPECT_FALSE(src_map_ptr->HasSource(0x5EBF, 0x6030));
  EXPECT_FALSE(src_map_ptr->HasSource(0x6031, 0x608D));
  EXPECT_FALSE(src_map_ptr->HasSource(0x608E, 0x609E));
  EXPECT_FALSE(src_map_ptr->HasSource(0x609F, 0x60B3));
  EXPECT_FALSE(src_map_ptr->HasSource(0x60B4, 0x60BD));
}

TEST_F(WasmModuleSourceMapTest, HasValidEntry) {
  char src_map[] =
      "{\"version\":3,\"sources\":[\"./"
      "test.h\",\"main.cpp\"],\"names\":[],\"mappings\":\"6/"
      "BAGA,0DAIA,2DAIA,IAEA,+BACA,wCADA,mBAGA,4CCXA,6BACA,IACA,4BACA,gBADA,"
      "mBAIA,4BACA,QADA,mBAIA,4BACA,gBADA,mBAVA,mBAcA\"}";
  auto i_isolate = isolate();
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(i_isolate);
  auto src_map_str =
      v8::String::NewFromUtf8(v8_isolate, src_map).ToLocalChecked();
  std::unique_ptr<WasmModuleSourceMap> src_map_ptr(
      new WasmModuleSourceMap(v8_isolate, src_map_str));
  EXPECT_TRUE(src_map_ptr->IsValid());

  EXPECT_FALSE(src_map_ptr->HasValidEntry(0x450, 0x467));
  EXPECT_FALSE(src_map_ptr->HasValidEntry(0x450, 0x450));
  EXPECT_TRUE(src_map_ptr->HasValidEntry(0x450, 0x47A));
  EXPECT_TRUE(src_map_ptr->HasValidEntry(0x450, 0x4A9));
  EXPECT_FALSE(src_map_ptr->HasValidEntry(0x4DE, 0x4F5));
  EXPECT_TRUE(src_map_ptr->HasValidEntry(0x4DE, 0x541));
  EXPECT_TRUE(src_map_ptr->HasValidEntry(0x4DE, 0x57D));
  EXPECT_TRUE(src_map_ptr->HasValidEntry(0x4DE, 0x5B7));
  EXPECT_FALSE(src_map_ptr->HasValidEntry(0x4DE, 0x4DE));
  EXPECT_TRUE(src_map_ptr->HasValidEntry(0x4DE, 0x500));
  EXPECT_TRUE(src_map_ptr->HasValidEntry(0x4DE, 0x521));
  EXPECT_TRUE(src_map_ptr->HasValidEntry(0x4DE, 0x560));
  EXPECT_TRUE(src_map_ptr->HasValidEntry(0x4DE, 0x597));
}

TEST_F(WasmModuleSourceMapTest, GetFilename) {
  char src_map[] =
      "{\"version\":3,\"sources\":[\"./"
      "test.h\",\"main.cpp\"],\"names\":[],\"mappings\":\"6/"
      "BAGA,0DAIA,2DAIA,IAEA,+BACA,wCADA,mBAGA,4CCXA,6BACA,IACA,4BACA,gBADA,"
      "mBAIA,4BACA,QADA,mBAIA,4BACA,gBADA,mBAVA,mBAcA\"}";
  auto i_isolate = isolate();
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(i_isolate);
  auto src_map_str =
      v8::String::NewFromUtf8(v8_isolate, src_map).ToLocalChecked();
  std::unique_ptr<WasmModuleSourceMap> src_map_ptr(
      new WasmModuleSourceMap(v8_isolate, src_map_str));
  EXPECT_TRUE(src_map_ptr->IsValid());

  EXPECT_STREQ("./test.h", src_map_ptr->GetFilename(0x47A).c_str());
  EXPECT_STREQ("./test.h", src_map_ptr->GetFilename(0x4A9).c_str());
  EXPECT_STREQ("main.cpp", src_map_ptr->GetFilename(0x500).c_str());
  EXPECT_STREQ("main.cpp", src_map_ptr->GetFilename(0x521).c_str());
  EXPECT_STREQ("main.cpp", src_map_ptr->GetFilename(0x541).c_str());
  EXPECT_STREQ("main.cpp", src_map_ptr->GetFilename(0x560).c_str());
  EXPECT_STREQ("main.cpp", src_map_ptr->GetFilename(0x57D).c_str());
  EXPECT_STREQ("main.cpp", src_map_ptr->GetFilename(0x597).c_str());
  EXPECT_STREQ("main.cpp", src_map_ptr->GetFilename(0x5B7).c_str());
}

TEST_F(WasmModuleSourceMapTest, SourceLine) {
  char src_map[] =
      "{\"version\":3,\"sources\":[\"./"
      "test.h\",\"main.cpp\"],\"names\":[],\"mappings\":\"6/"
      "BAGA,0DAIA,2DAIA,IAEA,+BACA,wCADA,mBAGA,4CCXA,6BACA,IACA,4BACA,gBADA,"
      "mBAIA,4BACA,QADA,mBAIA,4BACA,gBADA,mBAVA,mBAcA\"}";
  auto i_isolate = isolate();
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(i_isolate);
  auto src_map_str =
      v8::String::NewFromUtf8(v8_isolate, src_map).ToLocalChecked();
  std::unique_ptr<WasmModuleSourceMap> src_map_ptr(
      new WasmModuleSourceMap(v8_isolate, src_map_str));
  EXPECT_TRUE(src_map_ptr->IsValid());

  EXPECT_EQ(13ul, src_map_ptr->GetSourceLine(0x47A));
  EXPECT_EQ(14ul, src_map_ptr->GetSourceLine(0x4A9));
  EXPECT_EQ(5ul, src_map_ptr->GetSourceLine(0x500));
  EXPECT_EQ(7ul, src_map_ptr->GetSourceLine(0x521));
  EXPECT_EQ(8ul, src_map_ptr->GetSourceLine(0x541));
  EXPECT_EQ(11ul, src_map_ptr->GetSourceLine(0x560));
  EXPECT_EQ(12ul, src_map_ptr->GetSourceLine(0x57D));
  EXPECT_EQ(15ul, src_map_ptr->GetSourceLine(0x597));
  EXPECT_EQ(16ul, src_map_ptr->GetSourceLine(0x5B7));
}
}  // namespace wasm
}  // namespace internal
}  // namespace v8
```