Response: Let's break down the thought process to arrive at the explanation of the C++ code.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and its relation to JavaScript, with a JavaScript example. The file path `v8/test/cctest/wasm/test-run-wasm-bulk-memory.cc` strongly suggests it's a testing file for WebAssembly's bulk memory operations.

2. **High-Level Structure Analysis:** The code starts with copyright and includes, which confirm it's a V8 (JavaScript engine) test. The namespace `v8::internal::wasm::test_run_wasm_bulk_memory` further reinforces the WebAssembly testing context. The `WASM_EXEC_TEST` and `WASM_COMPILED_EXEC_TEST` macros are key indicators of individual test cases.

3. **Identify Core Functionality:**  Skimming through the test names and the operations within them reveals keywords like "MemoryInit", "MemoryCopy", "MemoryFill", "DataDrop", and "TableCopy". These directly map to WebAssembly instructions for manipulating memory and tables.

4. **Analyze Helper Functions:**  The code defines `CheckMemoryEquals`, `CheckMemoryEqualsZero`, and `CheckMemoryEqualsFollowedByZeroes`. These are clearly utility functions for asserting the state of the WebAssembly memory after specific operations. They help verify if the memory manipulation instructions work correctly. The `CheckTable` and `CheckTableCall` functions do a similar job for WebAssembly tables.

5. **Decipher Individual Tests:**  Now, let's go through some representative tests:
    * **`MemoryInit`:** This test uses `WASM_MEMORY_INIT`. It initializes memory from a *passive data segment*. This immediately suggests a connection to the JavaScript `WebAssembly.Memory` and data segments.
    * **`MemoryCopy`:** This test utilizes `WASM_MEMORY0_COPY`, indicating memory-to-memory copying within the same linear memory.
    * **`MemoryFill`:**  `WASM_MEMORY_FILL` is used to fill a region of memory with a specific byte value.
    * **`DataDrop`:** `WASM_DATA_DROP` drops (makes inaccessible) a passive data segment.
    * **`TableCopy`:** `WASM_TABLE_COPY` is used to copy entries between WebAssembly tables.

6. **Connect to JavaScript:**  Now, the crucial step: relating these C++ tests to JavaScript functionality.
    * **Memory Operations:**  The `memory.init`, `memory.copy`, and `memory.fill` WebAssembly instructions directly correspond to the C++ tests. The JavaScript `WebAssembly.Memory` object and its underlying buffer are the targets of these operations.
    * **Data Segments:** The "passive data segment" mentioned in `MemoryInit` relates to the `<data>` element in the WebAssembly text format or the `WebAssembly.Module`'s `dataSegments` property. These segments are loaded and then can be copied into memory using `memory.init`.
    * **Tables:** The `table.copy` instruction corresponds to the C++ `TableCopy` tests. JavaScript's `WebAssembly.Table` object is the entity being manipulated here.

7. **Construct the JavaScript Example:** Based on the `MemoryInit` test, a good JavaScript example would demonstrate:
    * Creating a `WebAssembly.Memory` object.
    * Defining a WebAssembly module with a data segment and the `memory.init` instruction.
    * Instantiating the module.
    * Calling the exported function that executes the `memory.init` instruction.
    * Accessing the `WebAssembly.Memory`'s `buffer` (using a `Uint8Array`) to verify the data has been copied.

8. **Refine and Organize the Explanation:**  Structure the explanation clearly:
    * Start with a concise summary.
    * Explain the core functionalities (`memory.init`, `memory.copy`, `memory.fill`, `data.drop`, `table.copy`).
    * Provide the JavaScript example with clear steps and explanations.
    * Elaborate on the connection between the C++ code and JavaScript concepts.
    * Mention the testing nature of the C++ code.

9. **Review and Verify:** Double-check the accuracy of the JavaScript example and the explanations. Ensure the terminology aligns with WebAssembly specifications. For example, "passive data segment" is the correct term.

This thought process, starting from high-level understanding and progressively drilling down into specifics, while constantly making connections to the target language (JavaScript in this case), allows for a comprehensive and accurate explanation of the provided C++ code.
这个C++源代码文件 `test-run-wasm-bulk-memory.cc` 是 V8 JavaScript 引擎的测试文件，专门用于测试 WebAssembly 的 **批量内存操作 (Bulk Memory Operations)**。

**功能归纳:**

该文件包含多个测试用例，每个用例都构建一个简单的 WebAssembly 模块，并执行包含批量内存操作指令的函数，然后检查内存或表的预期状态，以验证这些指令的正确性。

测试的主要 WebAssembly 指令包括：

* **`memory.init`**:  从一个被动的（passive）数据段初始化内存的某个区域。
* **`memory.copy`**: 将内存的某个区域复制到另一个区域。
* **`memory.fill`**: 使用给定的字节值填充内存的某个区域。
* **`data.drop`**:  使一个被动的数据段变为不可访问状态。
* **`table.copy`**: 将一个表的一部分复制到另一个表（或同一个表）。

**具体测试用例覆盖的场景包括：**

* **`MemoryInit`**:
    * 从数据段复制数据到内存的不同位置。
    * 复制 0 字节的情况。
    * 复制操作的边界情况。
    * 尝试越界访问数据段或内存的情况。
* **`MemoryCopy`**:
    * 在内存的不同位置之间复制数据。
    * 复制 0 字节的情况。
    * 复制操作的边界情况。
    * 源和目标内存区域重叠的情况。
    * 尝试越界访问内存的情况。
* **`MemoryFill`**:
    * 使用特定值填充内存的不同区域。
    * 填充 0 字节的情况。
    * 填充值的截断（只使用低 8 位）。
    * 尝试越界填充内存的情况。
* **`DataDrop`**:
    * 多次丢弃同一个数据段。
    * 丢弃数据段后尝试使用 `memory.init` 初始化内存。
* **`TableCopy`**:
    * 在同一个表的内部复制元素。
    * 在不同表之间复制元素。
    * 复制过程中元素的覆盖情况。
    * 测试复制后能否正确调用表中的函数。
    * 尝试越界复制表元素的情况。

**与 Javascript 的关系 (以及 Javascript 示例):**

WebAssembly 旨在在现代 Web 浏览器中运行，并与 JavaScript 紧密集成。 这些 C++ 测试用例直接测试了 WebAssembly 引擎在执行对应的 WebAssembly 指令时的行为。  这些指令可以通过 JavaScript 的 `WebAssembly` API 来创建和执行。

**JavaScript 示例 (对应 `MemoryInit` 测试):**

```javascript
async function runWasmMemoryInit() {
  const memory = new WebAssembly.Memory({ initial: 1 }); // 创建一个初始大小为 1 页的内存

  const wasmCode = `
    (module
      (memory (import "env" "memory") 1)
      (data (i32.const 0) "\\00\\01\\02\\03\\04\\05\\06\\07\\08\\09") ;; 定义一个被动数据段
      (func (export "initMemory") (local $dest i32) (local $sourceOffset i32) (local $length i32)
        local.get $dest
        local.get $sourceOffset
        local.get $length
        memory.init 0  ;; 使用数据段 0 初始化内存
      )
    )
  `;

  const wasmModule = await WebAssembly.compile(new TextEncoder().encode(wasmCode));
  const wasmInstance = await WebAssembly.instantiate(wasmModule, { env: { memory: memory } });

  const memoryBuffer = new Uint8Array(memory.buffer);

  // 初始状态，内存应该全是 0
  console.log("Initial memory:", memoryBuffer.slice(0, 20));

  // 调用 wasm 函数，将数据段的数据复制到内存的偏移量 10，长度为 10
  wasmInstance.exports.initMemory(10, 0, 10);

  // 检查内存是否被正确初始化
  console.log("Memory after init:", memoryBuffer.slice(0, 20)); // 应该看到偏移量 10 开始有数据

  // 预期输出 (Memory after init):
  // Uint8Array(20) [
  //   0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  //   0, 1, 2, 3, 4, 5, 6, 7, 8, 9
  // ]
}

runWasmMemoryInit();
```

**解释示例:**

1. **创建 `WebAssembly.Memory`**:  JavaScript 代码创建了一个 WebAssembly 内存实例，它对应了 wasm 模块中导入的 `memory`。
2. **定义 wasm 模块**:  `wasmCode` 定义了一个 wasm 模块。
   - `(memory (import "env" "memory") 1)`: 导入一个名为 "memory" 的内存。
   - `(data (i32.const 0) "\\00\\01\\02\\03\\04\\05\\06\\07\\08\\09")`: 定义了一个被动数据段（索引为 0），内容是 0 到 9 的字节。
   - `(func (export "initMemory") ... memory.init 0)`: 定义了一个导出的函数 `initMemory`，它接收目标地址、源偏移量和长度，并使用 `memory.init 0` 指令将数据段 0 的内容复制到内存中。
3. **编译和实例化**: 使用 `WebAssembly.compile` 和 `WebAssembly.instantiate` 将 wasm 代码编译并实例化。
4. **获取内存缓冲区**: `new Uint8Array(memory.buffer)` 创建了一个可以访问 wasm 内存的 `Uint8Array`。
5. **调用 wasm 函数**: `wasmInstance.exports.initMemory(10, 0, 10)` 调用 wasm 模块导出的 `initMemory` 函数，指示将数据段 0 的前 10 个字节复制到 wasm 内存的偏移量 10 处。
6. **检查内存**:  通过查看 `memoryBuffer` 的内容，可以验证 `memory.init` 指令是否按预期工作。

总而言之， `test-run-wasm-bulk-memory.cc` 是 V8 引擎中用于确保 WebAssembly 的批量内存操作指令在各种情况下都能正确执行的关键测试文件。 它通过构建 wasm 模块并在 C++ 环境中执行，来验证 wasm 引擎的实现是否符合 WebAssembly 规范。 这些指令的功能可以通过 JavaScript 的 `WebAssembly` API 在 Web 环境中使用。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-bulk-memory.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/wasm-module-builder.h"
#include "test/cctest/cctest.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8 {
namespace internal {
namespace wasm {
namespace test_run_wasm_bulk_memory {

namespace {
void CheckMemoryEquals(TestingModuleBuilder* builder, size_t index,
                       const std::vector<uint8_t>& expected) {
  const uint8_t* mem_start = builder->raw_mem_start<uint8_t>();
  const uint8_t* mem_end = builder->raw_mem_end<uint8_t>();
  size_t mem_size = mem_end - mem_start;
  CHECK_LE(index, mem_size);
  CHECK_LE(index + expected.size(), mem_size);
  for (size_t i = 0; i < expected.size(); ++i) {
    CHECK_EQ(expected[i], mem_start[index + i]);
  }
}

void CheckMemoryEqualsZero(TestingModuleBuilder* builder, size_t index,
                           size_t length) {
  const uint8_t* mem_start = builder->raw_mem_start<uint8_t>();
  const uint8_t* mem_end = builder->raw_mem_end<uint8_t>();
  size_t mem_size = mem_end - mem_start;
  CHECK_LE(index, mem_size);
  CHECK_LE(index + length, mem_size);
  for (size_t i = 0; i < length; ++i) {
    CHECK_EQ(0, mem_start[index + i]);
  }
}

void CheckMemoryEqualsFollowedByZeroes(TestingModuleBuilder* builder,
                                       const std::vector<uint8_t>& expected) {
  CheckMemoryEquals(builder, 0, expected);
  CheckMemoryEqualsZero(builder, expected.size(),
                        builder->mem_size() - expected.size());
}
}  // namespace

WASM_EXEC_TEST(MemoryInit) {
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  const uint8_t data[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  r.builder().AddPassiveDataSegment(base::ArrayVector(data));
  r.Build({WASM_MEMORY_INIT(0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                            WASM_LOCAL_GET(2)),
           kExprI32Const, 0});

  // All zeroes.
  CheckMemoryEqualsZero(&r.builder(), 0, kWasmPageSize);

  // Copy all bytes from data segment 0, to memory at [10, 20).
  CHECK_EQ(0, r.Call(10, 0, 10));
  CheckMemoryEqualsFollowedByZeroes(
      &r.builder(),
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9});

  // Copy bytes in range [5, 10) from data segment 0, to memory at [0, 5).
  CHECK_EQ(0, r.Call(0, 5, 5));
  CheckMemoryEqualsFollowedByZeroes(
      &r.builder(),
      {5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9});

  // Copy 0 bytes does nothing.
  CHECK_EQ(0, r.Call(10, 1, 0));
  CheckMemoryEqualsFollowedByZeroes(
      &r.builder(),
      {5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9});

  // Copy 0 at end of memory region or data segment is OK.
  CHECK_EQ(0, r.Call(kWasmPageSize, 0, 0));
  CHECK_EQ(0, r.Call(0, sizeof(data), 0));
}

WASM_EXEC_TEST(MemoryInitOutOfBoundsData) {
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  const uint8_t data[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  r.builder().AddPassiveDataSegment(base::ArrayVector(data));
  r.Build({WASM_MEMORY_INIT(0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                            WASM_LOCAL_GET(2)),
           kExprI32Const, 0});

  const uint32_t last_5_bytes = kWasmPageSize - 5;

  // Failing memory.init should not have any effect.
  CHECK_EQ(0xDEADBEEF, r.Call(kWasmPageSize - 5, 0, 6));
  CheckMemoryEquals(&r.builder(), last_5_bytes, {0, 0, 0, 0, 0});

  r.builder().BlankMemory();
  CHECK_EQ(0xDEADBEEF, r.Call(0, 5, 6));
  CheckMemoryEquals(&r.builder(), last_5_bytes, {0, 0, 0, 0, 0});
}

WASM_EXEC_TEST(MemoryInitOutOfBounds) {
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  const uint8_t data[kWasmPageSize] = {};
  r.builder().AddPassiveDataSegment(base::ArrayVector(data));
  r.Build({WASM_MEMORY_INIT(0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                            WASM_LOCAL_GET(2)),
           kExprI32Const, 0});

  // OK, copy the full data segment to memory.
  r.Call(0, 0, kWasmPageSize);

  // Source range must not be out of bounds.
  CHECK_EQ(0xDEADBEEF, r.Call(0, 1, kWasmPageSize));
  CHECK_EQ(0xDEADBEEF, r.Call(0, 1000, kWasmPageSize));
  CHECK_EQ(0xDEADBEEF, r.Call(0, kWasmPageSize, 1));

  // Destination range must not be out of bounds.
  CHECK_EQ(0xDEADBEEF, r.Call(1, 0, kWasmPageSize));
  CHECK_EQ(0xDEADBEEF, r.Call(1000, 0, kWasmPageSize));
  CHECK_EQ(0xDEADBEEF, r.Call(kWasmPageSize, 0, 1));

  // Copy 0 out-of-bounds fails if target is invalid.
  CHECK_EQ(0xDEADBEEF, r.Call(kWasmPageSize + 1, 0, 0));
  CHECK_EQ(0xDEADBEEF, r.Call(0, kWasmPageSize + 1, 0));

  // Make sure bounds aren't checked with 32-bit wrapping.
  CHECK_EQ(0xDEADBEEF, r.Call(1, 1, 0xFFFFFFFF));
}

WASM_EXEC_TEST(MemoryCopy) {
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  uint8_t* mem = r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_MEMORY0_COPY(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                             WASM_LOCAL_GET(2)),
           kExprI32Const, 0});

  const uint8_t initial[] = {0, 11, 22, 33, 44, 55, 66, 77};
  memcpy(mem, initial, sizeof(initial));

  // Copy from [1, 8] to [10, 16].
  CHECK_EQ(0, r.Call(10, 1, 8));
  CheckMemoryEqualsFollowedByZeroes(
      &r.builder(),
      {0, 11, 22, 33, 44, 55, 66, 77, 0, 0, 11, 22, 33, 44, 55, 66, 77});

  // Copy 0 bytes does nothing.
  CHECK_EQ(0, r.Call(10, 2, 0));
  CheckMemoryEqualsFollowedByZeroes(
      &r.builder(),
      {0, 11, 22, 33, 44, 55, 66, 77, 0, 0, 11, 22, 33, 44, 55, 66, 77});

  // Copy 0 at end of memory region is OK.
  CHECK_EQ(0, r.Call(kWasmPageSize, 0, 0));
  CHECK_EQ(0, r.Call(0, kWasmPageSize, 0));
}

WASM_EXEC_TEST(MemoryCopyOverlapping) {
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  uint8_t* mem = r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_MEMORY0_COPY(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                             WASM_LOCAL_GET(2)),
           kExprI32Const, 0});

  const uint8_t initial[] = {10, 20, 30};
  memcpy(mem, initial, sizeof(initial));

  // Copy from [0, 3] -> [2, 5]. The copy must not overwrite 30 before copying
  // it (i.e. cannot copy forward in this case).
  CHECK_EQ(0, r.Call(2, 0, 3));
  CheckMemoryEqualsFollowedByZeroes(&r.builder(), {10, 20, 10, 20, 30});

  // Copy from [2, 5] -> [0, 3]. The copy must not write the first 10 (i.e.
  // cannot copy backward in this case).
  CHECK_EQ(0, r.Call(0, 2, 3));
  CheckMemoryEqualsFollowedByZeroes(&r.builder(), {10, 20, 30, 20, 30});
}

WASM_EXEC_TEST(MemoryCopyOutOfBoundsData) {
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  uint8_t* mem = r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_MEMORY0_COPY(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                             WASM_LOCAL_GET(2)),
           kExprI32Const, 0});

  const uint8_t data[] = {11, 22, 33, 44, 55, 66, 77, 88};
  memcpy(mem, data, sizeof(data));

  const uint32_t last_5_bytes = kWasmPageSize - 5;

  CheckMemoryEquals(&r.builder(), last_5_bytes, {0, 0, 0, 0, 0});
  CHECK_EQ(0xDEADBEEF, r.Call(last_5_bytes, 0, 6));
  CheckMemoryEquals(&r.builder(), last_5_bytes, {0, 0, 0, 0, 0});

  r.builder().BlankMemory();
  memcpy(mem + last_5_bytes, data, 5);
  CHECK_EQ(0xDEADBEEF, r.Call(0, last_5_bytes, kWasmPageSize));
  CheckMemoryEquals(&r.builder(), last_5_bytes, {11, 22, 33, 44, 55});

  r.builder().BlankMemory();
  memcpy(mem + last_5_bytes, data, 5);
  CHECK_EQ(0xDEADBEEF, r.Call(last_5_bytes, 0, kWasmPageSize));
  CheckMemoryEquals(&r.builder(), last_5_bytes, {11, 22, 33, 44, 55});
}

WASM_EXEC_TEST(MemoryCopyOutOfBounds) {
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_MEMORY0_COPY(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                             WASM_LOCAL_GET(2)),
           kExprI32Const, 0});

  // Copy full range is OK.
  CHECK_EQ(0, r.Call(0, 0, kWasmPageSize));

  // Source range must not be out of bounds.
  CHECK_EQ(0xDEADBEEF, r.Call(0, 1, kWasmPageSize));
  CHECK_EQ(0xDEADBEEF, r.Call(0, 1000, kWasmPageSize));
  CHECK_EQ(0xDEADBEEF, r.Call(0, kWasmPageSize, 1));

  // Destination range must not be out of bounds.
  CHECK_EQ(0xDEADBEEF, r.Call(1, 0, kWasmPageSize));
  CHECK_EQ(0xDEADBEEF, r.Call(1000, 0, kWasmPageSize));
  CHECK_EQ(0xDEADBEEF, r.Call(kWasmPageSize, 0, 1));

  // Copy 0 out-of-bounds fails if target is invalid.
  CHECK_EQ(0xDEADBEEF, r.Call(kWasmPageSize + 1, 0, 0));
  CHECK_EQ(0xDEADBEEF, r.Call(0, kWasmPageSize + 1, 0));

  // Make sure bounds aren't checked with 32-bit wrapping.
  CHECK_EQ(0xDEADBEEF, r.Call(1, 1, 0xFFFFFFFF));
}

WASM_EXEC_TEST(MemoryFill) {
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_MEMORY_FILL(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                            WASM_LOCAL_GET(2)),
           kExprI32Const, 0});
  CHECK_EQ(0, r.Call(1, 33, 5));
  CheckMemoryEqualsFollowedByZeroes(&r.builder(), {0, 33, 33, 33, 33, 33});

  CHECK_EQ(0, r.Call(4, 66, 4));
  CheckMemoryEqualsFollowedByZeroes(&r.builder(),
                                    {0, 33, 33, 33, 66, 66, 66, 66});

  // Fill 0 bytes does nothing.
  CHECK_EQ(0, r.Call(4, 66, 0));
  CheckMemoryEqualsFollowedByZeroes(&r.builder(),
                                    {0, 33, 33, 33, 66, 66, 66, 66});

  // Fill 0 at end of memory region is OK.
  CHECK_EQ(0, r.Call(kWasmPageSize, 66, 0));
}

WASM_EXEC_TEST(MemoryFillValueWrapsToByte) {
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_MEMORY_FILL(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                            WASM_LOCAL_GET(2)),
           kExprI32Const, 0});
  CHECK_EQ(0, r.Call(0, 1000, 3));
  const uint8_t expected = 1000 & 255;
  CheckMemoryEqualsFollowedByZeroes(&r.builder(),
                                    {expected, expected, expected});
}

WASM_EXEC_TEST(MemoryFillOutOfBoundsData) {
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_MEMORY_FILL(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                            WASM_LOCAL_GET(2)),
           kExprI32Const, 0});
  const uint8_t v = 123;
  CHECK_EQ(0xDEADBEEF, r.Call(kWasmPageSize - 5, v, 999));
  CheckMemoryEquals(&r.builder(), kWasmPageSize - 6, {0, 0, 0, 0, 0, 0});
}

WASM_EXEC_TEST(MemoryFillOutOfBounds) {
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_MEMORY_FILL(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                            WASM_LOCAL_GET(2)),
           kExprI32Const, 0});

  const uint8_t v = 123;

  // Destination range must not be out of bounds.
  CHECK_EQ(0xDEADBEEF, r.Call(1, v, kWasmPageSize));
  CHECK_EQ(0xDEADBEEF, r.Call(1000, v, kWasmPageSize));
  CHECK_EQ(0xDEADBEEF, r.Call(kWasmPageSize, v, 1));

  // Fill 0 out-of-bounds still fails.
  CHECK_EQ(0xDEADBEEF, r.Call(kWasmPageSize + 1, v, 0));

  // Make sure bounds aren't checked with 32-bit wrapping.
  CHECK_EQ(0xDEADBEEF, r.Call(1, v, 0xFFFFFFFF));
}

WASM_EXEC_TEST(DataDropTwice) {
  WasmRunner<uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  const uint8_t data[] = {0};
  r.builder().AddPassiveDataSegment(base::ArrayVector(data));
  r.Build({WASM_DATA_DROP(0), kExprI32Const, 0});

  CHECK_EQ(0, r.Call());
  CHECK_EQ(0, r.Call());
}

WASM_EXEC_TEST(DataDropThenMemoryInit) {
  WasmRunner<uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  const uint8_t data[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  r.builder().AddPassiveDataSegment(base::ArrayVector(data));
  r.Build({WASM_DATA_DROP(0),
           WASM_MEMORY_INIT(0, WASM_I32V_1(0), WASM_I32V_1(1), WASM_I32V_1(2)),
           kExprI32Const, 0});

  CHECK_EQ(0xDEADBEEF, r.Call());
}

void TestTableCopyInbounds(TestExecutionTier execution_tier, int table_dst,
                           int table_src) {
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  const uint32_t kTableSize = 5;
  // Add 10 function tables, even though we only test one table.
  for (int i = 0; i < 10; ++i) {
    r.builder().AddIndirectFunctionTable(nullptr, kTableSize);
  }
  r.Build({WASM_TABLE_COPY(table_dst, table_src, WASM_LOCAL_GET(0),
                           WASM_LOCAL_GET(1), WASM_LOCAL_GET(2)),
           kExprI32Const, 0});

  for (uint32_t i = 0; i <= kTableSize; ++i) {
    r.CheckCallViaJS(0, 0, 0, i);  // nop
    r.CheckCallViaJS(0, 0, i, kTableSize - i);
    r.CheckCallViaJS(0, i, 0, kTableSize - i);
  }
}

WASM_COMPILED_EXEC_TEST(TableCopyInboundsFrom0To0) {
  TestTableCopyInbounds(execution_tier, 0, 0);
}

WASM_COMPILED_EXEC_TEST(TableCopyInboundsFrom3To0) {
  TestTableCopyInbounds(execution_tier, 3, 0);
}

WASM_COMPILED_EXEC_TEST(TableCopyInboundsFrom5To9) {
  TestTableCopyInbounds(execution_tier, 5, 9);
}

WASM_COMPILED_EXEC_TEST(TableCopyInboundsFrom6To6) {
  TestTableCopyInbounds(execution_tier, 6, 6);
}

namespace {
template <typename... Args>
void CheckTable(Isolate* isolate, DirectHandle<WasmTableObject> table,
                Args... args) {
  uint32_t args_length = static_cast<uint32_t>(sizeof...(args));
  CHECK_EQ(table->current_length(), args_length);
  Handle<Object> handles[] = {args...};
  for (uint32_t i = 0; i < args_length; ++i) {
    CHECK(WasmTableObject::Get(isolate, table, i).is_identical_to(handles[i]));
  }
}

template <typename WasmRunner, typename... Args>
void CheckTableCall(Isolate* isolate, DirectHandle<WasmTableObject> table,
                    WasmRunner* r, uint32_t function_index, Args... args) {
  uint32_t args_length = static_cast<uint32_t>(sizeof...(args));
  CHECK_EQ(table->current_length(), args_length);
  double expected[] = {args...};
  for (uint32_t i = 0; i < args_length; ++i) {
    Handle<Object> buffer[] = {isolate->factory()->NewNumber(i)};
    r->CheckCallApplyViaJS(expected[i], function_index, buffer, 1);
  }
}
}  // namespace

void TestTableCopyElems(TestExecutionTier execution_tier, int table_dst,
                        int table_src) {
  Isolate* isolate = CcTest::InitIsolateOnce();
  HandleScope scope(isolate);
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  const uint32_t kTableSize = 5;
  uint16_t function_indexes[kTableSize];
  const ModuleTypeIndex sig_index = r.builder().AddSignature(sigs.i_v());

  for (uint32_t i = 0; i < kTableSize; ++i) {
    WasmFunctionCompiler& fn = r.NewFunction(sigs.i_v(), "f");
    fn.Build({WASM_I32V_1(i)});
    fn.SetSigIndex(sig_index);
    function_indexes[i] = fn.function_index();
  }

  for (int i = 0; i < 10; ++i) {
    r.builder().AddIndirectFunctionTable(function_indexes, kTableSize);
  }

  r.Build({WASM_TABLE_COPY(table_dst, table_src, WASM_LOCAL_GET(0),
                           WASM_LOCAL_GET(1), WASM_LOCAL_GET(2)),
           kExprI32Const, 0});

  r.builder().InitializeWrapperCache();

  auto table =
      handle(Cast<WasmTableObject>(
                 r.builder().trusted_instance_data()->tables()->get(table_dst)),
             isolate);
  r.CheckCallViaJS(0, 0, 0, kTableSize);
  auto f0 = WasmTableObject::Get(isolate, table, 0);
  auto f1 = WasmTableObject::Get(isolate, table, 1);
  auto f2 = WasmTableObject::Get(isolate, table, 2);
  auto f3 = WasmTableObject::Get(isolate, table, 3);
  auto f4 = WasmTableObject::Get(isolate, table, 4);

  if (table_dst == table_src) {
    CheckTable(isolate, table, f0, f1, f2, f3, f4);
    r.CheckCallViaJS(0, 0, 1, 1);
    CheckTable(isolate, table, f1, f1, f2, f3, f4);
    r.CheckCallViaJS(0, 0, 1, 2);
    CheckTable(isolate, table, f1, f2, f2, f3, f4);
    r.CheckCallViaJS(0, 3, 0, 2);
    CheckTable(isolate, table, f1, f2, f2, f1, f2);
    r.CheckCallViaJS(0, 1, 0, 2);
    CheckTable(isolate, table, f1, f1, f2, f1, f2);
  } else {
    CheckTable(isolate, table, f0, f1, f2, f3, f4);
    r.CheckCallViaJS(0, 0, 1, 1);
    CheckTable(isolate, table, f1, f1, f2, f3, f4);
    r.CheckCallViaJS(0, 0, 1, 2);
    CheckTable(isolate, table, f1, f2, f2, f3, f4);
    r.CheckCallViaJS(0, 3, 0, 2);
    CheckTable(isolate, table, f1, f2, f2, f0, f1);
    r.CheckCallViaJS(0, 1, 0, 2);
    CheckTable(isolate, table, f1, f0, f1, f0, f1);
  }
}

WASM_COMPILED_EXEC_TEST(TableCopyElemsFrom0To0) {
  TestTableCopyElems(execution_tier, 0, 0);
}

WASM_COMPILED_EXEC_TEST(TableCopyElemsFrom3To0) {
  TestTableCopyElems(execution_tier, 3, 0);
}

WASM_COMPILED_EXEC_TEST(TableCopyElemsFrom5To9) {
  TestTableCopyElems(execution_tier, 5, 9);
}

WASM_COMPILED_EXEC_TEST(TableCopyElemsFrom6To6) {
  TestTableCopyElems(execution_tier, 6, 6);
}

void TestTableCopyCalls(TestExecutionTier execution_tier, int table_dst,
                        int table_src) {
  Isolate* isolate = CcTest::InitIsolateOnce();
  HandleScope scope(isolate);
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  const uint32_t kTableSize = 5;
  uint16_t function_indexes[kTableSize];
  const ModuleTypeIndex sig_index = r.builder().AddSignature(sigs.i_v());

  for (uint32_t i = 0; i < kTableSize; ++i) {
    WasmFunctionCompiler& fn = r.NewFunction(sigs.i_v(), "f");
    fn.Build({WASM_I32V_1(i)});
    fn.SetSigIndex(sig_index);
    function_indexes[i] = fn.function_index();
  }

  for (int i = 0; i < 10; ++i) {
    r.builder().AddIndirectFunctionTable(function_indexes, kTableSize);
  }

  WasmFunctionCompiler& call = r.NewFunction(sigs.i_i(), "call");
  call.Build(
      {WASM_CALL_INDIRECT_TABLE(table_dst, sig_index, WASM_LOCAL_GET(0))});
  const uint32_t call_index = call.function_index();

  r.Build({WASM_TABLE_COPY(table_dst, table_src, WASM_LOCAL_GET(0),
                           WASM_LOCAL_GET(1), WASM_LOCAL_GET(2)),
           kExprI32Const, 0});

  auto table =
      handle(Cast<WasmTableObject>(
                 r.builder().trusted_instance_data()->tables()->get(table_dst)),
             isolate);

  if (table_dst == table_src) {
    CheckTableCall(isolate, table, &r, call_index, 0.0, 1.0, 2.0, 3.0, 4.0);
    r.CheckCallViaJS(0, 0, 1, 1);
    CheckTableCall(isolate, table, &r, call_index, 1.0, 1.0, 2.0, 3.0, 4.0);
    r.CheckCallViaJS(0, 0, 1, 2);
    CheckTableCall(isolate, table, &r, call_index, 1.0, 2.0, 2.0, 3.0, 4.0);
    r.CheckCallViaJS(0, 3, 0, 2);
    CheckTableCall(isolate, table, &r, call_index, 1.0, 2.0, 2.0, 1.0, 2.0);
  } else {
    CheckTableCall(isolate, table, &r, call_index, 0.0, 1.0, 2.0, 3.0, 4.0);
    r.CheckCallViaJS(0, 0, 1, 1);
    CheckTableCall(isolate, table, &r, call_index, 1.0, 1.0, 2.0, 3.0, 4.0);
    r.CheckCallViaJS(0, 0, 1, 2);
    CheckTableCall(isolate, table, &r, call_index, 1.0, 2.0, 2.0, 3.0, 4.0);
    r.CheckCallViaJS(0, 3, 0, 2);
    CheckTableCall(isolate, table, &r, call_index, 1.0, 2.0, 2.0, 0.0, 1.0);
  }
}

WASM_COMPILED_EXEC_TEST(TableCopyCallsTo0From0) {
  TestTableCopyCalls(execution_tier, 0, 0);
}

WASM_COMPILED_EXEC_TEST(TableCopyCallsTo3From0) {
  TestTableCopyCalls(execution_tier, 3, 0);
}

WASM_COMPILED_EXEC_TEST(TableCopyCallsTo5From9) {
  TestTableCopyCalls(execution_tier, 5, 9);
}

WASM_COMPILED_EXEC_TEST(TableCopyCallsTo6From6) {
  TestTableCopyCalls(execution_tier, 6, 6);
}

void TestTableCopyOobWrites(TestExecutionTier execution_tier, int table_dst,
                            int table_src) {
  Isolate* isolate = CcTest::InitIsolateOnce();
  HandleScope scope(isolate);
  TestSignatures sigs;
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  const uint32_t kTableSize = 5;
  uint16_t function_indexes[kTableSize];
  const ModuleTypeIndex sig_index = r.builder().AddSignature(sigs.i_v());

  for (uint32_t i = 0; i < kTableSize; ++i) {
    WasmFunctionCompiler& fn = r.NewFunction(sigs.i_v(), "f");
    fn.Build({WASM_I32V_1(i)});
    fn.SetSigIndex(sig_index);
    function_indexes[i] = fn.function_index();
  }

  for (int i = 0; i < 10; ++i) {
    r.builder().AddIndirectFunctionTable(function_indexes, kTableSize);
  }

  r.Build({WASM_TABLE_COPY(table_dst, table_src, WASM_LOCAL_GET(0),
                           WASM_LOCAL_GET(1), WASM_LOCAL_GET(2)),
           kExprI32Const, 0});

  r.builder().InitializeWrapperCache();

  auto table =
      handle(Cast<WasmTableObject>(
                 r.builder().trusted_instance_data()->tables()->get(table_dst)),
             isolate);
  // Fill the dst table with values from the src table, to make checks easier.
  r.CheckCallViaJS(0, 0, 0, kTableSize);
  auto f0 = WasmTableObject::Get(isolate, table, 0);
  auto f1 = WasmTableObject::Get(isolate, table, 1);
  auto f2 = WasmTableObject::Get(isolate, table, 2);
  auto f3 = WasmTableObject::Get(isolate, table, 3);
  auto f4 = WasmTableObject::Get(isolate, table, 4);

  CheckTable(isolate, table, f0, f1, f2, f3, f4);

  // Failing table.copy should not have any effect.
  r.CheckCallViaJS(0xDEADBEEF, 3, 0, 3);
  CheckTable(isolate, table, f0, f1, f2, f3, f4);

  r.CheckCallViaJS(0xDEADBEEF, 0, 4, 2);
  CheckTable(isolate, table, f0, f1, f2, f3, f4);

  r.CheckCallViaJS(0xDEADBEEF, 3, 0, 99);
  CheckTable(isolate, table, f0, f1, f2, f3, f4);

  r.CheckCallViaJS(0xDEADBEEF, 0, 1, 99);
  CheckTable(isolate, table, f0, f1, f2, f3, f4);
}

WASM_COMPILED_EXEC_TEST(TableCopyOobWritesFrom0To0) {
  TestTableCopyOobWrites(execution_tier, 0, 0);
}

WASM_COMPILED_EXEC_TEST(TableCopyOobWritesFrom3To0) {
  TestTableCopyOobWrites(execution_tier, 3, 0);
}

WASM_COMPILED_EXEC_TEST(TableCopyOobWritesFrom5To9) {
  TestTableCopyOobWrites(execution_tier, 5, 9);
}

WASM_COMPILED_EXEC_TEST(TableCopyOobWritesFrom6To6) {
  TestTableCopyOobWrites(execution_tier, 6, 6);
}

void TestTableCopyOob1(TestExecutionTier execution_tier, int table_dst,
                       int table_src) {
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  const uint32_t kTableSize = 5;

  for (int i = 0; i < 10; ++i) {
    r.builder().AddIndirectFunctionTable(nullptr, kTableSize);
  }

  r.Build({WASM_TABLE_COPY(table_dst, table_src, WASM_LOCAL_GET(0),
                           WASM_LOCAL_GET(1), WASM_LOCAL_GET(2)),
           kExprI32Const, 0});

  r.CheckCallViaJS(0, 0, 0, 1);           // nop
  r.CheckCallViaJS(0, 0, 0, kTableSize);  // nop
  r.CheckCallViaJS(0xDEADBEEF, 0, 0, kTableSize + 1);
  r.CheckCallViaJS(0xDEADBEEF, 1, 0, kTableSize);
  r.CheckCallViaJS(0xDEADBEEF, 0, 1, kTableSize);

  {
    const uint32_t big = 1000000;
    r.CheckCallViaJS(0xDEADBEEF, big, 0, 0);
    r.CheckCallViaJS(0xDEADBEEF, 0, big, 0);
  }

  for (uint32_t big = 4294967295; big > 1000; big >>= 1) {
    r.CheckCallViaJS(0xDEADBEEF, big, 0, 1);
    r.CheckCallViaJS(0xDEADBEEF, 0, big, 1);
    r.CheckCallViaJS(0xDEADBEEF, 0, 0, big);
  }

  for (uint32_t big = -1000; big != 0; big <<= 1) {
    r.CheckCallViaJS(0xDEADBEEF, big, 0, 1);
    r.CheckCallViaJS(0xDEADBEEF, 0, big, 1);
    r.CheckCallViaJS(0xDEADBEEF, 0, 0, big);
  }
}

WASM_COMPILED_EXEC_TEST(TableCopyOob1From0To0) {
  TestTableCopyOob1(execution_tier, 0, 0);
}

WASM_COMPILED_EXEC_TEST(TableCopyOob1From3To0) {
  TestTableCopyOob1(execution_tier, 3, 0);
}

WASM_COMPILED_EXEC_TEST(TableCopyOob1From5To9) {
  TestTableCopyOob1(execution_tier, 5, 9);
}

WASM_COMPILED_EXEC_TEST(TableCopyOob1From6To6) {
  TestTableCopyOob1(execution_tier, 6, 6);
}

}  // namespace test_run_wasm_bulk_memory
}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```