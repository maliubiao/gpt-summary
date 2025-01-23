Response:
Let's break down the thought process for analyzing this C++ V8 test file.

**1. Initial Skim and Identification of Core Functionality:**

The first step is to quickly read through the code, paying attention to:

* **Includes:**  `wasm-module-builder.h`, `cctest.h`, `wasm-run-utils.h`, `test-signatures.h`, `wasm-macro-gen.h`. These strongly suggest this is a WebAssembly testing file within the V8 project. The "bulk_memory" in the filename is also a key indicator.
* **Namespaces:** `v8::internal::wasm::test_run_wasm_bulk_memory`. This confirms the WebAssembly context and identifies the specific test suite.
* **`WASM_EXEC_TEST` and `WASM_COMPILED_EXEC_TEST` macros:** These are clearly test case definitions. The names of the tests (`MemoryInit`, `MemoryCopy`, `TableCopyInbounds`, etc.) give direct clues about what's being tested.
* **Core Operations:** Look for specific Wasm instructions being used within the `Build` methods, such as `WASM_MEMORY_INIT`, `WASM_MEMORY0_COPY`, `WASM_MEMORY_FILL`, `WASM_DATA_DROP`, `WASM_TABLE_COPY`, `WASM_CALL_INDIRECT_TABLE`.

From this initial skim, the core functionality is clearly related to testing WebAssembly's bulk memory operations and table operations.

**2. Analyzing Individual Test Cases:**

The next step is to go through each `WASM_EXEC_TEST` and `WASM_COMPILED_EXEC_TEST` individually. For each test, ask:

* **What operation is being tested?**  (Look at the `WASM_*` macro in the `Build` method).
* **What are the inputs to the Wasm function?** (The arguments to `r.Call` or `r.CheckCallViaJS`). These often represent memory offsets, lengths, or table indices.
* **What are the expected outcomes?** (The `CheckMemoryEquals`, `CheckMemoryEqualsZero`, and `CheckTable` functions are used for verification. `CHECK_EQ(0, r.Call(...))` indicates a successful operation, while `CHECK_EQ(0xDEADBEEF, r.Call(...))` indicates an expected failure/trap).
* **What edge cases or boundary conditions are being tested?** Look for tests with "OutOfBounds," "Overlapping," "Twice," etc. These tests specifically target potential error scenarios.

**Example: Analyzing `WASM_EXEC_TEST(MemoryInit)`:**

* **Operation:** `WASM_MEMORY_INIT` (initializes a region of linear memory from a data segment).
* **Inputs to Wasm:** Three `uint32_t` values, which the comments and later `r.Call` invocations reveal are the destination offset, source offset within the data segment, and the number of bytes to copy.
* **Expected Outcomes:**
    * Initially, the memory is zeroed out.
    * After the first `r.Call`, the first 10 bytes of the data segment are copied to memory starting at offset 10.
    * After the second `r.Call`, 5 bytes from the middle of the data segment are copied to the beginning of memory.
    * The test also checks that copying 0 bytes does nothing and that copying 0 bytes at the end of memory or data segment is allowed.
* **Edge Cases:**  The test covers copying the entire data segment, a portion of it, and zero bytes.

**3. Identifying Connections to JavaScript (If Any):**

Look for instances of `CheckCallViaJS`. This strongly suggests the test involves interacting with the Wasm module from JavaScript. In the table copy tests, the code is explicitly checking the values within the Wasm table by calling back into JavaScript.

**4. Inferring Code Logic and Providing Examples:**

Based on the test names and the Wasm instructions used, infer the underlying logic of the Wasm bulk memory operations. Translate this logic into a simple JavaScript example. For instance, `MemoryInit` is analogous to `Uint8Array.set` or copying portions of an `ArrayBuffer`.

**5. Identifying Common Programming Errors:**

Focus on the tests with "OutOfBounds." These directly highlight common mistakes like trying to access memory or data segments outside their valid ranges. The "Overlapping" test pinpoints a more subtle error related to incorrect assumptions about the order of memory copying.

**6. Handling the ".tq" Question:**

The question about the `.tq` extension is a simple check of file naming conventions in V8. The provided file clearly ends in `.cc`, so it's C++ and not Torque. Explain the significance of `.tq` if it were present.

**7. Structuring the Output:**

Organize the findings into clear sections as requested by the prompt:

* **Functionality:** Provide a high-level overview.
* **.tq Check:** Address the filename extension question.
* **JavaScript Relation:**  Give concrete JavaScript examples.
* **Code Logic and I/O:** Provide illustrative examples with hypothetical inputs and outputs.
* **Common Errors:** Explain common pitfalls with examples.

**Self-Correction/Refinement During the Process:**

* **Initial Misinterpretations:**  Sometimes, the initial interpretation of a test name or instruction might be slightly off. Carefully examining the code and the assertions will usually clarify the intent.
* **Missing Details:** Ensure you've covered all the tests and haven't skipped over important aspects.
* **Clarity and Conciseness:**  Strive for clear and concise explanations, avoiding unnecessary jargon. Use simple language in the JavaScript examples.

By following these steps systematically, you can effectively analyze and understand the functionality of a V8 test file like `test-run-wasm-bulk-memory.cc`.
`v8/test/cctest/wasm/test-run-wasm-bulk-memory.cc` is a C++ source file containing **integration tests for WebAssembly bulk memory operations** within the V8 JavaScript engine.

Here's a breakdown of its functionality:

**Core Functionality:**

This file tests the correct behavior of the following WebAssembly instructions related to bulk memory manipulation:

* **`memory.init`**:  Copies a region of bytes from a passive data segment into linear memory.
* **`memory.copy`**: Copies a region of bytes from one location in linear memory to another.
* **`memory.fill`**: Fills a region of linear memory with a specified byte value.
* **`data.drop`**:  Releases the resources associated with a passive data segment.
* **`table.copy`**: Copies entries from one function table to another.

**Key Aspects Tested:**

The tests in this file cover various scenarios for these instructions, including:

* **Basic Functionality:** Verifying that the instructions perform the intended operations correctly under normal conditions.
* **Boundary Conditions:** Testing behavior when accessing the beginning, end, or zero-length regions of memory or data segments.
* **Out-of-Bounds Access:** Checking that attempts to access memory or data segments outside their valid ranges are handled correctly (typically by trapping, indicated by `CHECK_EQ(0xDEADBEEF, r.Call(...))`).
* **Overlapping Memory Regions (`memory.copy`):** Ensuring that copying between overlapping memory regions produces the correct result, regardless of whether the source and destination overlap.
* **Data Segment Management (`data.drop` and `memory.init`):**  Testing that data segments can be dropped and that accessing a dropped data segment results in an error.
* **Table Copying:** Verifying that function table entries are copied correctly, including cases where the source and destination tables are the same.
* **Table Copying with Function Calls:**  Testing that after a `table.copy`, indirect calls through the modified table execute the correct functions.
* **Table Out-of-Bounds Access:** Checking that attempts to copy or access elements outside the bounds of the function tables are handled correctly.

**Is it a Torque source file?**

No, `v8/test/cctest/wasm/test-run-wasm-bulk-memory.cc` ends with `.cc`, which is the standard file extension for C++ source files in V8. If it ended with `.tq`, then it would be a V8 Torque source file.

**Relationship to JavaScript and Examples:**

These WebAssembly bulk memory operations directly correspond to functionalities that can be exposed and used within JavaScript when working with WebAssembly modules.

**JavaScript Examples:**

```javascript
// Assuming you have a compiled WebAssembly module instance 'wasmInstance'
// with memory and data segments defined.

// Equivalent to memory.init
const memory = wasmInstance.exports.memory;
const dataSegmentId = 0; // Assuming a data segment with id 0
const destinationOffset = 10;
const sourceOffsetInDataSegment = 0;
const lengthToCopy = 5;

// In JavaScript, you'd typically need to fetch the data segment content
// and then use TypedArrays to manipulate memory.
// This is a simplified illustration, the actual implementation details
// might involve more steps depending on how the data segment is exposed.
const dataSegment = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
const memoryBuffer = new Uint8Array(memory.buffer);

for (let i = 0; i < lengthToCopy; ++i) {
  memoryBuffer[destinationOffset + i] = dataSegment[sourceOffsetInDataSegment + i];
}

// Equivalent to memory.copy
const destOffsetCopy = 20;
const sourceOffsetCopy = 10;
const lengthToCopyCopy = 5;

memoryBuffer.copyWithin(destOffsetCopy, sourceOffsetCopy, sourceOffsetCopy + lengthToCopyCopy);

// Equivalent to memory.fill
const fillOffset = 30;
const fillValue = 0xAA; // Example byte value
const fillLength = 5;

for (let i = 0; i < fillLength; ++i) {
  memoryBuffer[fillOffset + i] = fillValue;
}

// data.drop doesn't have a direct JavaScript equivalent for the same level of control.
// Once a data segment is dropped in WebAssembly, it's no longer accessible.
// In JavaScript, you might simulate this by managing data separately.

// table.copy involves function tables, which are more complex to illustrate directly in simple JS.
// It relates to how indirect calls are resolved in WebAssembly.
```

**Code Logic Inference with Assumptions and Examples:**

Let's take the `WASM_EXEC_TEST(MemoryInit)` as an example:

**Assumptions:**

* `kWasmPageSize` is the standard WebAssembly page size (65536 bytes).
* The data segment with index 0 contains the bytes `[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]`.
* The Wasm function takes three `uint32_t` arguments: destination offset, source offset in the data segment, and length.

**Hypothetical Input and Output for `r.Call(10, 0, 10)`:**

* **Input:**
    * Destination Offset (local 0): 10
    * Source Offset (local 1): 0
    * Length (local 2): 10
* **Expected Output:** The `memory.init` instruction will copy 10 bytes from data segment 0, starting at index 0, to linear memory starting at index 10. The `CheckMemoryEqualsFollowedByZeroes` function will then verify that the memory from index 0 up to where the copy ends matches the expected pattern, with the rest of the memory being zeroed.

**Hypothetical Input and Output for `r.Call(0, 5, 5)`:**

* **Input:**
    * Destination Offset (local 0): 0
    * Source Offset (local 1): 5
    * Length (local 2): 5
* **Expected Output:** The `memory.init` instruction will copy 5 bytes from data segment 0, starting at index 5 (bytes `[5, 6, 7, 8, 9]`), to linear memory starting at index 0. The `CheckMemoryEqualsFollowedByZeroes` will verify the memory content.

**User-Specific Programming Errors Illustrated:**

The tests in this file directly demonstrate common programming errors when working with WebAssembly memory:

1. **Out-of-Bounds Memory Access (`MemoryInitOutOfBounds`, `MemoryCopyOutOfBounds`, `MemoryFillOutOfBounds`):**

   ```c++
   // Example from MemoryInitOutOfBoundsData
   WASM_EXEC_TEST(MemoryInitOutOfBoundsData) {
     // ...
     // Trying to copy 6 bytes from data segment 0 starting at offset 0
     // to memory starting at kWasmPageSize - 5. This will go beyond the
     // allocated memory.
     CHECK_EQ(0xDEADBEEF, r.Call(kWasmPageSize - 5, 0, 6));
     // ...
   }
   ```

   **JavaScript Analogy:**

   ```javascript
   const memoryBuffer = new Uint8Array(wasmInstance.exports.memory.buffer);
   const destinationOffset = memoryBuffer.length - 5;
   const lengthToCopy = 6;
   const sourceData = [0, 1, 2, 3, 4, 5];

   // This will result in an error because the write goes beyond the buffer's bounds
   for (let i = 0; i < lengthToCopy; ++i) {
     memoryBuffer[destinationOffset + i] = sourceData[i]; // Potential error here
   }
   ```

2. **Out-of-Bounds Data Segment Access (`MemoryInitOutOfBoundsData`):**

   ```c++
   // Example from MemoryInitOutOfBoundsData
   WASM_EXEC_TEST(MemoryInitOutOfBoundsData) {
     // ...
     const uint8_t data[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
     // ...
     // Trying to copy 6 bytes from data segment 0 starting at offset 5.
     // This attempts to read beyond the end of the data segment.
     CHECK_EQ(0xDEADBEEF, r.Call(0, 5, 6));
     // ...
   }
   ```

   **JavaScript Analogy (conceptual):**  If you were manually managing the data segment:

   ```javascript
   const dataSegment = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
   const sourceOffset = 5;
   const lengthToCopy = 6;

   // This would try to access dataSegment[5], dataSegment[6], ..., dataSegment[10]
   // which is beyond the bounds of the dataSegment array.
   const sourceSlice = dataSegment.slice(sourceOffset, sourceOffset + lengthToCopy);
   ```

3. **Incorrectly Handling Overlapping Memory Regions (`MemoryCopyOverlapping`):**

   ```c++
   // Example from MemoryCopyOverlapping
   WASM_EXEC_TEST(MemoryCopyOverlapping) {
     // ...
     // Copy from [0, 3] -> [2, 5]. If not handled correctly, the initial
     // value at memory[2] might be overwritten before being copied.
     CHECK_EQ(0, r.Call(2, 0, 3));
     // ...
   }
   ```

   **JavaScript Analogy:**

   ```javascript
   const memoryBuffer = new Uint8Array([10, 20, 30]);
   const sourceOffset = 0;
   const destinationOffset = 2;
   const lengthToCopy = 3;

   // Naive (and incorrect) implementation for overlapping copy:
   for (let i = 0; i < lengthToCopy; ++i) {
     memoryBuffer[destinationOffset + i] = memoryBuffer[sourceOffset + i];
   }
   // This would result in [10, 20, 10, 20, 30] instead of the correct [10, 20, 10, 20, 30]
   // because the 30 is overwritten too early.
   ```

4. **Using Dropped Data Segments (`DataDropThenMemoryInit`):**

   ```c++
   WASM_EXEC_TEST(DataDropThenMemoryInit) {
     // ...
     r.Build({WASM_DATA_DROP(0),
              WASM_MEMORY_INIT(0, WASM_I32V_1(0), WASM_I32V_1(1), WASM_I32V_1(2)),
              kExprI32Const, 0});
     CHECK_EQ(0xDEADBEEF, r.Call()); // Attempting to use the dropped data segment
   }
   ```

   **JavaScript Analogy (conceptual):**  If you had a way to explicitly drop data segments:

   ```javascript
   // Hypothetical:
   wasmInstance.dropDataSegment(0);
   // Attempting to access or initialize memory from the dropped segment would fail.
   ```

In summary, `v8/test/cctest/wasm/test-run-wasm-bulk-memory.cc` plays a crucial role in ensuring the reliability and correctness of WebAssembly's bulk memory and table manipulation features within the V8 engine by thoroughly testing various valid and invalid usage scenarios.

### 提示词
```
这是目录为v8/test/cctest/wasm/test-run-wasm-bulk-memory.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm-bulk-memory.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
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
```