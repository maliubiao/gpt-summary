Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/wasm/test-streaming-compilation.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The file name `test-streaming-compilation.cc` strongly suggests the code is testing the streaming compilation feature of WebAssembly in V8.

2. **Analyze Individual Test Cases:** Each `STREAM_TEST` macro likely defines a specific scenario for testing streaming compilation. I need to go through each one and understand what it's testing. Key things to look for in each test:
    * How the WebAssembly module is constructed (using raw bytes or a builder).
    * How the bytes are fed to the `StreamTester` (using `OnBytesReceived`).
    * Whether `FinishStream` is called.
    * Whether `Abort` is called and when.
    * Whether compiler tasks are run (`RunCompilerTasks`).
    * What the expected outcome is (`IsPromiseFulfilled`, `IsPromiseRejected`).

3. **Look for Common Themes:**  Group the tests by the specific aspect of streaming compilation they are verifying. For example, several tests seem to be related to aborting the streaming process at different stages. Others focus on error handling, caching, or the basic successful compilation.

4. **Connect to JavaScript (if applicable):** Streaming compilation is a feature that directly impacts how WebAssembly modules are loaded and executed in a JavaScript environment. I need to think about how a developer would interact with this feature from JavaScript (e.g., using `WebAssembly.compileStreaming`).

5. **Identify Potential Programming Errors:**  Based on the test scenarios, I can infer common mistakes developers might make when working with streaming compilation or WebAssembly in general (e.g., providing invalid module bytes).

6. **Address Specific Constraints:** The prompt mentions `.tq` files (Torque), but this file is `.cc`, so that point is irrelevant. The prompt also requests JavaScript examples if there's a connection, code logic with inputs/outputs, and common errors.

7. **Structure the Summary:** Organize the findings into clear categories as requested by the user: functionality, JavaScript examples, code logic, and common errors.

**Detailed Analysis of Each Test Case:**

* **`TestAbortBeforeCodeSection`:**  Aborts the streaming process before the code section is provided. Tests handling of premature aborts.
* **`TestAbortBeforeFunctionGotCompiled`:** Aborts after the initial module structure but before function code. Tests aborts during compilation setup.
* **`TestAbortAfterFunctionGotCompiled1` & `TestAbortAfterFunctionGotCompiled2`:** Aborts after some functions have started compilation. Tests aborting mid-compilation. The "invalid body size" in the second suggests testing how aborts interact with compilation errors.
* **`TestAbortAfterCodeSection1` & `TestAbortAfterCodeSection2`:** Aborts after all code has been received. Tests aborting after what should be a complete module.
* **`TestAbortAfterCompilationError1` & `TestAbortAfterCompilationError2`:** Aborts after encountering a compilation error. Tests how aborts interact with errors during compilation.
* **`TestOnlyModuleHeader`:**  Tests a minimal valid WebAssembly module (just the header). Checks if the streaming process can handle this.
* **`TestModuleWithZeroFunctions`:** Tests a valid module with no functions. Ensures the streaming process works correctly for empty function sections.
* **`TestModuleWithMultipleFunctions`:** Tests a standard case with multiple functions, ensuring correct streaming and compilation.
* **`TestModuleWithDataSection`:** Tests a module with a data section, confirming correct handling of different sections.
* **`TestModuleWithImportedFunction`:** Tests a module that imports a function, checking if streaming handles imports.
* **`TestIncrementalCaching`:**  Focuses on testing the incremental caching mechanism during streaming compilation, especially with dynamic tiering enabled. It verifies the `MoreFunctionsCanBeSerializedCallback` is triggered and that cached modules are smaller after tier-up.
* **`TestModuleWithErrorAfterDataSection`:** Tests error handling when an invalid section appears after the data section.
* **`TestDeserializationBypassesCompilation`:** Tests the scenario where a pre-compiled module is available, and streaming uses the cached version instead of compiling from scratch.
* **`TestDeserializationFails`:**  Tests how streaming handles a failure during deserialization of a cached module, ensuring it falls back to compiling the wire bytes.
* **`TestFunctionSectionWithoutCodeSection`:** Tests the error condition of having a function section but no corresponding code section.
* **`TestMoreFunctionsCanBeSerializedCallback`:**  Specifically tests that the `MoreFunctionsCanBeSerializedCallback` is called when dynamic tiering is enabled and functions are ready to be cached.
* **`TestMoreFunctionsCanBeSerializedCallbackWithTimeout`:**  Tests the timeout mechanism associated with the `MoreFunctionsCanBeSerializedCallback`, ensuring the callback isn't triggered too frequently.
* **`TestHardCachingThreshold`:** Tests the "hard" caching threshold, which likely triggers caching based on the total size of compiled code, rather than individual function sizes.

By analyzing these tests, I can build a comprehensive summary of the file's functionality.
好的，这是对提供的v8源代码 `v8/test/cctest/wasm/test-streaming-compilation.cc` 的功能归纳，基于你提供的第二部分代码：

**功能归纳 (基于提供的第二部分代码):**

这部分代码主要集中在测试 WebAssembly 模块的流式编译过程中**中断 (Abort)** 的各种场景，以及一些**成功的流式编译**和**缓存**相关的测试。  具体来说，它测试了以下几种情况下的中断行为：

* **在代码段 (Code Section) 之前中断:** 验证在接收到所有模块头信息但尚未接收到函数代码时中断流式编译的处理。
* **在函数开始编译之前中断:**  测试在开始编译任何函数之前就中断流式编译的情况。
* **在部分函数编译完成后中断:** 模拟在某些函数已经完成编译但其他函数还在编译过程中中断流式编译，以及中断后编译任务的处理。
* **在所有函数编译完成后中断:** 测试在整个代码段都被接收并完成编译后中断流式编译的情形。
* **在遇到编译错误后中断:** 验证在流式编译过程中遇到错误后中断的处理，以及后续编译任务的处理。

除了中断测试，这部分代码还包含了以下功能的测试：

* **仅有模块头:** 测试只接收到 WebAssembly 模块头的情况，验证流式编译的最小有效输入。
* **零函数模块:**  测试包含类型、函数和代码段但函数数量为零的模块，确保流式编译能正确处理空函数列表。
* **多函数模块:**  测试包含多个函数的标准 WebAssembly 模块的流式编译。
* **包含数据段的模块:** 测试包含数据段的 WebAssembly 模块的流式编译，验证对不同段的处理。
* **包含导入函数的模块:** 测试包含导入函数的 WebAssembly 模块的流式编译。
* **增量缓存 (Incremental Caching):** 测试 WebAssembly 的增量缓存机制，验证在流式编译过程中，部分编译完成的函数可以被缓存，并在后续使用。
* **数据段后有错误的模块:** 测试在数据段之后出现未知或错误段时的流式编译错误处理。
* **反序列化绕过编译 (Deserialization Bypasses Compilation):** 测试当存在已编译的模块缓存时，流式编译是否能直接使用缓存而跳过编译过程。
* **反序列化失败 (Deserialization Fails):** 测试当已编译的模块缓存损坏或无效时，流式编译是否会回退到重新编译。
* **没有代码段的函数段 (Function Section Without Code Section):** 测试存在函数段但缺少代码段的错误情况。
* **`MoreFunctionsCanBeSerializedCallback` 回调:** 测试在动态分层编译 (dynamic tiering) 启用时，`MoreFunctionsCanBeSerializedCallback` 回调函数是否会被正确触发，以通知可以序列化更多函数。
* **带超时的 `MoreFunctionsCanBeSerializedCallback` 回调:** 测试 `MoreFunctionsCanBeSerializedCallback` 回调函数的超时机制，确保回调不会过于频繁触发。
* **硬缓存阈值 (Hard Caching Threshold):** 测试硬缓存阈值，当达到该阈值时，即使未达到常规的缓存条件，也会触发缓存回调。

**与 JavaScript 的关系:**

流式编译是 JavaScript 中加载 WebAssembly 模块的一种方式。JavaScript 中可以使用 `WebAssembly.compileStreaming()` 函数来发起流式编译。

```javascript
async function loadWasm(url) {
  try {
    const response = await fetch(url);
    const wasmModule = await WebAssembly.compileStreaming(response);
    const instance = await WebAssembly.instantiate(wasmModule);
    return instance.exports;
  } catch (error) {
    console.error("加载 WebAssembly 模块失败:", error);
  }
}

// 示例用法
loadWasm('my-wasm-module.wasm').then(exports => {
  // 使用导出的函数
  console.log(exports.add(5, 3));
});
```

在这个例子中，`WebAssembly.compileStreaming(response)` 就使用了流式编译。V8 的 `test-streaming-compilation.cc` 中的测试用例模拟了 `compileStreaming` 过程中可能发生的各种情况，包括正常编译、中断、错误和缓存等。

**代码逻辑推理 (假设输入与输出):**

以 `STREAM_TEST(TestAbortBeforeCodeSection)` 为例：

**假设输入:**

* `bytes`: 包含 WebAssembly 模块头、类型段和函数段的字节数组，但不包含代码段。

**预期输出:**

* 流式编译过程被中断。
* `tester.stream()->Abort()` 被调用。
* `tester.IsPromiseRejected()` 返回 true，表示编译失败。

**用户常见的编程错误 (举例说明):**

1. **提供不完整的 WebAssembly 模块:**  用户可能在网络传输或其他过程中意外截断了 WebAssembly 模块的字节流，导致 `WebAssembly.compileStreaming()` 接收到的数据不完整，这类似于测试用例中手动中断的情况。

   ```javascript
   async function loadIncompleteWasm(url) {
     try {
       const response = await fetch(url);
       const reader = response.body.getReader();
       const { value, done } = await reader.read();
       // 只传递部分数据
       const incompleteResponse = new Response(new Uint8Array(value.slice(0, value.length / 2)));
       const wasmModule = await WebAssembly.compileStreaming(incompleteResponse);
       // ...
     } catch (error) {
       console.error("加载不完整的 WebAssembly 模块失败:", error); // 预期会抛出错误
     }
   }
   ```

2. **服务端提前关闭连接:** 在流式传输 WebAssembly 模块时，如果服务端在传输完成之前关闭连接，也会导致客户端接收到不完整的模块，从而导致编译错误，这与测试用例中 `Abort()` 的行为类似。

3. **错误的模块结构:**  用户可能手动创建 WebAssembly 模块的字节数组，但结构不正确，例如函数段声明了函数数量，但代码段的数量不匹配，或者代码段中的函数体格式错误，这类似于测试用例中故意创建的错误代码。

**总结这部分代码的功能:**

总而言之，提供的 `v8/test/cctest/wasm/test-streaming-compilation.cc` 的第二部分代码专注于**测试 WebAssembly 流式编译过程中的中断机制以及一些成功的编译和缓存场景**。它通过模拟各种接收字节流的状态和人为触发中断，来验证 V8 引擎在处理这些情况时的正确性和健壮性。同时，它也涵盖了基本的流式编译成功场景和增量缓存的测试。这些测试确保了 V8 引擎能够可靠地处理各种可能在实际应用中发生的流式编译情况。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-streaming-compilation.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-streaming-compilation.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
dy
  };

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 3),                      // section size
      U32V_1(3),                          // functions count
      0,                                  // signature index
      0,                                  // signature index
      0,                                  // signature index
      kCodeSectionCode,                   // section code
      U32V_1(20),                         // section size
      U32V_1(3),                          // functions count
  };
  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.OnBytesReceived(code, arraysize(code));
  tester.RunCompilerTasks();
  tester.stream()->Abort();
  tester.RunCompilerTasks();
}

// Test Abort after some functions got compiled. The compiler tasks execute
// before the abort.
STREAM_TEST(TestAbortAfterFunctionGotCompiled2) {
  StreamTester tester(isolate);

  uint8_t code[] = {
      U32V_1(4),                  // !!! invalid body size !!!
      U32V_1(0),                  // locals count
      kExprLocalGet, 0, kExprEnd  // body
  };

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 3),                      // section size
      U32V_1(3),                          // functions count
      0,                                  // signature index
      0,                                  // signature index
      0,                                  // signature index
      kCodeSectionCode,                   // section code
      U32V_1(20),                         // section size
      U32V_1(3),                          // functions count
  };
  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.OnBytesReceived(code, arraysize(code));
  tester.stream()->Abort();
  tester.RunCompilerTasks();
}

// Test Abort after all functions got compiled.
STREAM_TEST(TestAbortAfterCodeSection1) {
  StreamTester tester(isolate);

  uint8_t code[] = {
      U32V_1(4),                  // body size
      U32V_1(0),                  // locals count
      kExprLocalGet, 0, kExprEnd  // body
  };

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 3),                      // section size
      U32V_1(3),                          // functions count
      0,                                  // signature index
      0,                                  // signature index
      0,                                  // signature index
      kCodeSectionCode,                   // section code
      U32V_1(1 + arraysize(code) * 3),    // section size
      U32V_1(3),                          // functions count
  };

  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(code, arraysize(code));
  tester.RunCompilerTasks();
  tester.stream()->Abort();
  tester.RunCompilerTasks();
}

// Test Abort after all functions got compiled.
STREAM_TEST(TestAbortAfterCodeSection2) {
  StreamTester tester(isolate);

  uint8_t code[] = {
      U32V_1(4),                  // body size
      U32V_1(0),                  // locals count
      kExprLocalGet, 0, kExprEnd  // body
  };

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 3),                      // section size
      U32V_1(3),                          // functions count
      0,                                  // signature index
      0,                                  // signature index
      0,                                  // signature index
      kCodeSectionCode,                   // section code
      U32V_1(1 + arraysize(code) * 3),    // section size
      U32V_1(3),                          // functions count
  };

  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(code, arraysize(code));
  tester.stream()->Abort();
  tester.RunCompilerTasks();
}

STREAM_TEST(TestAbortAfterCompilationError1) {
  StreamTester tester(isolate);

  uint8_t code[] = {
      U32V_1(4),                  // !!! invalid body size !!!
      U32V_1(0),                  // locals count
      kExprLocalGet, 0, kExprEnd  // body
  };

  uint8_t invalid_code[] = {
      U32V_1(4),                  // !!! invalid body size !!!
      U32V_1(0),                  // locals count
      kExprI64Const, 0, kExprEnd  // body
  };

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 3),                      // section size
      U32V_1(3),                          // functions count
      0,                                  // signature index
      0,                                  // signature index
      0,                                  // signature index
      kCodeSectionCode,                   // section code
      U32V_1(1 + arraysize(code) * 2 +
             arraysize(invalid_code)),  // section size
      U32V_1(3),                        // functions count
  };

  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(invalid_code, arraysize(invalid_code));
  tester.OnBytesReceived(code, arraysize(code));
  tester.RunCompilerTasks();
  tester.stream()->Abort();
  tester.RunCompilerTasks();
}

STREAM_TEST(TestAbortAfterCompilationError2) {
  StreamTester tester(isolate);

  uint8_t code[] = {
      U32V_1(4),                  // !!! invalid body size !!!
      U32V_1(0),                  // locals count
      kExprLocalGet, 0, kExprEnd  // body
  };

  uint8_t invalid_code[] = {
      U32V_1(4),                  // !!! invalid body size !!!
      U32V_1(0),                  // locals count
      kExprI64Const, 0, kExprEnd  // body
  };

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 3),                      // section size
      U32V_1(3),                          // functions count
      0,                                  // signature index
      0,                                  // signature index
      0,                                  // signature index
      kCodeSectionCode,                   // section code
      U32V_1(1 + arraysize(code) * 2 +
             arraysize(invalid_code)),  // section size
      U32V_1(3),                        // functions count
  };

  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(invalid_code, arraysize(invalid_code));
  tester.OnBytesReceived(code, arraysize(code));
  tester.stream()->Abort();
  tester.RunCompilerTasks();
}

STREAM_TEST(TestOnlyModuleHeader) {
  StreamTester tester(isolate);

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,  // module header
  };

  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.FinishStream();
  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseFulfilled());
}

STREAM_TEST(TestModuleWithZeroFunctions) {
  StreamTester tester(isolate);

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,    // module header
      kTypeSectionCode,      // section code
      U32V_1(1),             // section size
      U32V_1(0),             // type count
      kFunctionSectionCode,  // section code
      U32V_1(1),             // section size
      U32V_1(0),             // functions count
      kCodeSectionCode,      // section code
      U32V_1(1),             // section size
      U32V_1(0),             // functions count
  };

  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.FinishStream();
  tester.RunCompilerTasks();
  CHECK(tester.IsPromiseFulfilled());
}

STREAM_TEST(TestModuleWithMultipleFunctions) {
  StreamTester tester(isolate);

  uint8_t code[] = {
      U32V_1(4),                  // body size
      U32V_1(0),                  // locals count
      kExprLocalGet, 0, kExprEnd  // body
  };

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 3),                      // section size
      U32V_1(3),                          // functions count
      0,                                  // signature index
      0,                                  // signature index
      0,                                  // signature index
      kCodeSectionCode,                   // section code
      U32V_1(1 + arraysize(code) * 3),    // section size
      U32V_1(3),                          // functions count
  };

  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(code, arraysize(code));
  tester.RunCompilerTasks();
  tester.OnBytesReceived(code, arraysize(code));
  tester.FinishStream();
  tester.RunCompilerTasks();
  CHECK(tester.IsPromiseFulfilled());
}

STREAM_TEST(TestModuleWithDataSection) {
  StreamTester tester(isolate);

  uint8_t code[] = {
      U32V_1(4),                  // body size
      U32V_1(0),                  // locals count
      kExprLocalGet, 0, kExprEnd  // body
  };

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 3),                      // section size
      U32V_1(3),                          // functions count
      0,                                  // signature index
      0,                                  // signature index
      0,                                  // signature index
      kCodeSectionCode,                   // section code
      U32V_1(1 + arraysize(code) * 3),    // section size
      U32V_1(3),                          // functions count
  };

  const uint8_t data_section[] = {
      kDataSectionCode,  // section code
      U32V_1(1),         // section size
      U32V_1(0),         // data segment count
  };
  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(code, arraysize(code));
  tester.RunCompilerTasks();
  tester.OnBytesReceived(data_section, arraysize(data_section));
  tester.RunCompilerTasks();
  tester.FinishStream();
  tester.RunCompilerTasks();
  CHECK(tester.IsPromiseFulfilled());
}
// Test that all bytes arrive before doing any compilation. FinishStream is
// called immediately.
STREAM_TEST(TestModuleWithImportedFunction) {
  StreamTester tester(isolate);
  ZoneBuffer buffer(tester.zone());
  TestSignatures sigs;
  WasmModuleBuilder builder(tester.zone());
  builder.AddImport(base::ArrayVector("Test"), sigs.i_iii());
  {
    WasmFunctionBuilder* f = builder.AddFunction(sigs.i_iii());
    f->EmitCode({kExprLocalGet, 0, kExprEnd});
  }
  builder.WriteTo(&buffer);

  tester.OnBytesReceived(buffer.begin(), buffer.end() - buffer.begin());
  tester.FinishStream();

  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseFulfilled());
}

STREAM_TEST(TestIncrementalCaching) {
  FLAG_VALUE_SCOPE(wasm_tier_up, false);
  constexpr int threshold = 10;  // 10 bytes
  FlagScope<int> caching_threshold(&v8_flags.wasm_caching_threshold, threshold);
  FlagScope<int> caching_hard_threshold(&v8_flags.wasm_caching_hard_threshold,
                                        threshold);
  StreamTester tester(isolate);
  int call_cache_counter = 0;
  tester.stream()->SetMoreFunctionsCanBeSerializedCallback(
      [&call_cache_counter](
          const std::shared_ptr<i::wasm::NativeModule>& native_module) {
        call_cache_counter++;
      });

  ZoneBuffer buffer(tester.zone());
  TestSignatures sigs;
  WasmModuleBuilder builder(tester.zone());
  builder.AddMemory(1);

  base::Vector<const char> function_names[] = {
      base::CStrVector("f0"), base::CStrVector("f1"), base::CStrVector("f2")};
  for (int i = 0; i < 3; ++i) {
    WasmFunctionBuilder* f = builder.AddFunction(sigs.v_v());

    constexpr int64_t val = 0x123456789abc;
    constexpr int index = 0x1234;
    uint8_t store_mem[] = {
        WASM_STORE_MEM(MachineType::Int64(), WASM_I32V(index), WASM_I64V(val))};
    constexpr uint32_t kStoreLength = 20;
    CHECK_EQ(kStoreLength, arraysize(store_mem));

    // Produce a store {threshold} many times to reach the caching threshold.
    constexpr uint32_t kCodeLength = kStoreLength * threshold + 1;
    uint8_t code[kCodeLength];
    for (int j = 0; j < threshold; ++j) {
      memcpy(code + (j * kStoreLength), store_mem, kStoreLength);
    }
    code[kCodeLength - 1] = WasmOpcode::kExprEnd;
    f->EmitCode(code, kCodeLength);
    builder.AddExport(function_names[i], f);
  }
  builder.WriteTo(&buffer);
  tester.OnBytesReceived(buffer.begin(), buffer.end() - buffer.begin());
  tester.FinishStream();
  tester.RunCompilerTasks();
  CHECK(tester.IsPromiseFulfilled());
  tester.native_module();
  constexpr base::Vector<const char> kNoSourceUrl{"", 0};
  Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  DirectHandle<Script> script = GetWasmEngine()->GetOrCreateScript(
      i_isolate, tester.shared_native_module(), kNoSourceUrl);
  Handle<WasmModuleObject> module_object =
      WasmModuleObject::New(i_isolate, tester.shared_native_module(), script);
  ErrorThrower thrower(i_isolate, "Instantiation");
  // We instantiated before, so the second instantiation must also succeed:
  DirectHandle<WasmInstanceObject> instance =
      GetWasmEngine()
          ->SyncInstantiate(i_isolate, &thrower, module_object, {}, {})
          .ToHandleChecked();
  CHECK(!thrower.error());

  WasmCodeRefScope code_scope;
  NativeModule* module = tester.native_module();
  CHECK(module->GetCode(0) == nullptr || module->GetCode(0)->is_liftoff());
  CHECK(module->GetCode(1) == nullptr || module->GetCode(1)->is_liftoff());
  CHECK(module->GetCode(2) == nullptr || module->GetCode(2)->is_liftoff());
  // No TurboFan compilation happened yet, and therefore no call to the cache.
  CHECK_EQ(0, call_cache_counter);
  i::wasm::TriggerTierUp(i_isolate, instance->trusted_data(i_isolate), 0);
  tester.RunCompilerTasks();
  CHECK(!module->GetCode(0)->is_liftoff());
  CHECK(module->GetCode(1) == nullptr || module->GetCode(1)->is_liftoff());
  CHECK(module->GetCode(2) == nullptr || module->GetCode(2)->is_liftoff());
  CHECK_EQ(1, call_cache_counter);
  size_t serialized_size;
  {
    i::wasm::WasmSerializer serializer(tester.native_module());
    serialized_size = serializer.GetSerializedNativeModuleSize();
  }
  i::wasm::TriggerTierUp(i_isolate, instance->trusted_data(i_isolate), 1);
  tester.RunCompilerTasks();
  CHECK(!module->GetCode(0)->is_liftoff());
  CHECK(!module->GetCode(1)->is_liftoff());
  CHECK(module->GetCode(2) == nullptr || module->GetCode(2)->is_liftoff());
  CHECK_EQ(2, call_cache_counter);
  {
    i::wasm::WasmSerializer serializer(tester.native_module());
    CHECK_LT(serialized_size, serializer.GetSerializedNativeModuleSize());
  }
}

STREAM_TEST(TestModuleWithErrorAfterDataSection) {
  StreamTester tester(isolate);

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 1),                      // section size
      U32V_1(1),                          // functions count
      0,                                  // signature index
      kCodeSectionCode,                   // section code
      U32V_1(6),                          // section size
      U32V_1(1),                          // functions count
      U32V_1(4),                          // body size
      U32V_1(0),                          // locals count
      kExprLocalGet,                      // some code
      0,                                  // some code
      kExprEnd,                           // some code
      kDataSectionCode,                   // section code
      U32V_1(1),                          // section size
      U32V_1(0),                          // data segment count
      kUnknownSectionCode,                // section code
      U32V_1(1),                          // invalid section size
  };

  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.FinishStream();
  tester.RunCompilerTasks();
  CHECK(tester.IsPromiseRejected());
}

// Test that cached bytes work.
STREAM_TEST(TestDeserializationBypassesCompilation) {
  StreamTester tester(isolate);
  ZoneBuffer wire_bytes = GetValidModuleBytes(tester.zone());
  ZoneBuffer module_bytes =
      GetValidCompiledModuleBytes(isolate, tester.zone(), wire_bytes);
  tester.SetCompiledModuleBytes(base::VectorOf(module_bytes));
  tester.OnBytesReceived(wire_bytes.begin(), wire_bytes.size());
  tester.FinishStream();

  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseFulfilled());
}

// Test that bad cached bytes don't cause compilation of wire bytes to fail.
STREAM_TEST(TestDeserializationFails) {
  StreamTester tester(isolate);
  ZoneBuffer wire_bytes = GetValidModuleBytes(tester.zone());
  ZoneBuffer module_bytes =
      GetValidCompiledModuleBytes(isolate, tester.zone(), wire_bytes);
  // corrupt header
  uint8_t first_byte = *module_bytes.begin();
  module_bytes.patch_u8(0, first_byte + 1);
  tester.SetCompiledModuleBytes(base::VectorOf(module_bytes));
  tester.OnBytesReceived(wire_bytes.begin(), wire_bytes.size());
  tester.FinishStream();

  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseFulfilled());
}

// Test that a non-empty function section with a missing code section fails.
STREAM_TEST(TestFunctionSectionWithoutCodeSection) {
  StreamTester tester(isolate);

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,                 // module header
      kTypeSectionCode,                   // section code
      U32V_1(1 + SIZEOF_SIG_ENTRY_x_x),   // section size
      U32V_1(1),                          // type count
      SIG_ENTRY_x_x(kI32Code, kI32Code),  // signature entry
      kFunctionSectionCode,               // section code
      U32V_1(1 + 3),                      // section size
      U32V_1(3),                          // functions count
      0,                                  // signature index
      0,                                  // signature index
      0,                                  // signature index
  };

  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.FinishStream();

  tester.RunCompilerTasks();

  CHECK(tester.IsPromiseRejected());
}

STREAM_TEST(TestMoreFunctionsCanBeSerializedCallback) {
  // The "more functions can be serialized" callback will only be triggered with
  // dynamic tiering, so skip this test if dynamic tiering is disabled.
  if (!v8_flags.wasm_dynamic_tiering) return;

  // Reduce the caching threshold to 10 bytes so that our three small functions
  // trigger caching.
  FlagScope<int> caching_threshold(&v8_flags.wasm_caching_threshold, 10);
  FlagScope<int> caching_hard_threshold(&v8_flags.wasm_caching_hard_threshold,
                                        10);
  StreamTester tester(isolate);
  bool callback_called = false;
  tester.stream()->SetMoreFunctionsCanBeSerializedCallback(
      [&callback_called](const std::shared_ptr<NativeModule> module) {
        callback_called = true;
      });

  uint8_t code[] = {
      ADD_COUNT(U32V_1(0),                   // locals count
                kExprLocalGet, 0, kExprEnd)  // body
  };

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,  // module header
      SECTION(Type,
              ENTRY_COUNT(1),                      // type count
              SIG_ENTRY_x_x(kI32Code, kI32Code)),  // signature entry
      SECTION(Function, ENTRY_COUNT(3), SIG_INDEX(0), SIG_INDEX(0),
              SIG_INDEX(0)),
      SECTION(Export, ENTRY_COUNT(3),                             // 3 exports
              ADD_COUNT('a'), kExternalFunction, FUNC_INDEX(0),   // "a" (0)
              ADD_COUNT('b'), kExternalFunction, FUNC_INDEX(1),   // "b" (1)
              ADD_COUNT('c'), kExternalFunction, FUNC_INDEX(2)),  // "c" (2)
      kCodeSectionCode,                 // section code
      U32V_1(1 + arraysize(code) * 3),  // section size
      U32V_1(3),                        // functions count
  };

  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(code, arraysize(code));

  tester.FinishStream();
  tester.RunCompilerTasks();
  CHECK(tester.IsPromiseFulfilled());

  // Continue executing functions (eventually triggering tier-up) until the
  // callback is called at least once.
  auto* i_isolate = CcTest::i_isolate();
  ErrorThrower thrower{i_isolate, "TestMoreFunctionsCanBeSerializedCallback"};
  Handle<WasmInstanceObject> instance =
      GetWasmEngine()
          ->SyncInstantiate(i_isolate, &thrower, tester.module_object(), {}, {})
          .ToHandleChecked();
  CHECK(!thrower.error());

  Handle<WasmExportedFunction> exported_functions[]{
      testing::GetExportedFunction(i_isolate, instance, "a").ToHandleChecked(),
      testing::GetExportedFunction(i_isolate, instance, "b").ToHandleChecked(),
      testing::GetExportedFunction(i_isolate, instance, "c").ToHandleChecked()};

  // If Liftoff is enabled, then the callback should only be called after
  // tiering up.
  CHECK_IMPLIES(v8_flags.liftoff, !callback_called);
  while (!callback_called) {
    for (Handle<WasmExportedFunction> exported_function : exported_functions) {
      Execution::Call(i_isolate, exported_function,
                      ReadOnlyRoots{i_isolate}.undefined_value_handle(), 0,
                      nullptr)
          .Check();
    }
    tester.RunCompilerTasks();
  }
}

STREAM_TEST(TestMoreFunctionsCanBeSerializedCallbackWithTimeout) {
  // The "more functions can be serialized" callback will only be triggered with
  // dynamic tiering, so skip this test if dynamic tiering is disabled.
  if (!v8_flags.wasm_dynamic_tiering) return;

  // Reduce the caching threshold to 10 bytes so that our three small functions
  // trigger caching.
  FlagScope<int> caching_threshold(&v8_flags.wasm_caching_threshold, 10);
  FlagScope<int> caching_hard_threshold(&v8_flags.wasm_caching_hard_threshold,
                                        10);
  // Set the caching timeout to 10ms.
  constexpr int kCachingTimeoutMs = 10;
  FlagScope<int> caching_timeout(&v8_flags.wasm_caching_timeout_ms,
                                 kCachingTimeoutMs);
  // Timeouts used in the test below.
  // 1) A very generous timeout during which we expect the caching callback to
  // be called. Some bots are really slow here, especially when executing other
  // tests in parallel, so choose a really large timeout. As we do not expect to
  // run into this timeout, this does not increase test execution time.
  constexpr int caching_expected_timeout_ms = 10'000;
  // 2) A smaller timeout during which we *do not* expect another caching event.
  // We expect to run into this timeout, so do not choose it too long. Also,
  // running into this timeout because it was chosen too small will only make
  // the test pass (flakily), so it is not too critical.
  constexpr int no_caching_expected_timeout_ms = 2 * kCachingTimeoutMs;

  // Use a semaphore to wait for the caching event on the main thread.
  base::Semaphore caching_was_triggered{0};
  StreamTester tester(isolate);
  base::TimeTicks last_time_callback_was_called;
  tester.stream()->SetMoreFunctionsCanBeSerializedCallback(
      [&](const std::shared_ptr<NativeModule> module) {
        base::TimeTicks now = base::TimeTicks::Now();
        int64_t ms_since_last_time =
            (now - last_time_callback_was_called).InMilliseconds();
        // The timeout should have been respected.
        CHECK_LE(kCachingTimeoutMs, ms_since_last_time);
        last_time_callback_was_called = now;
        caching_was_triggered.Signal();
      });

  // This is used when waiting for the semaphore to be signalled. We need to
  // continue running compiler tasks while waiting.
  auto WaitForCaching = [&caching_was_triggered, &tester](int ms) {
    constexpr base::TimeDelta oneMs = base::TimeDelta::FromMilliseconds(1);
    for (int waited_ms = 0; waited_ms < ms; ++waited_ms) {
      if (caching_was_triggered.WaitFor(oneMs)) return true;
      tester.RunCompilerTasks();
    }
    return false;
  };

  uint8_t code[] = {
      ADD_COUNT(U32V_1(0),                   // locals count
                kExprLocalGet, 0, kExprEnd)  // body
  };

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,  // module header
      SECTION(Type,
              ENTRY_COUNT(1),                      // type count
              SIG_ENTRY_x_x(kI32Code, kI32Code)),  // signature entry
      SECTION(Function, ENTRY_COUNT(3), SIG_INDEX(0), SIG_INDEX(0),
              SIG_INDEX(0)),
      SECTION(Export, ENTRY_COUNT(3),                             // 3 exports
              ADD_COUNT('a'), kExternalFunction, FUNC_INDEX(0),   // "a" (0)
              ADD_COUNT('b'), kExternalFunction, FUNC_INDEX(1),   // "b" (1)
              ADD_COUNT('c'), kExternalFunction, FUNC_INDEX(2)),  // "c" (2)
      kCodeSectionCode,                 // section code
      U32V_1(1 + arraysize(code) * 3),  // section size
      U32V_1(3),                        // functions count
  };

  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(code, arraysize(code));
  tester.OnBytesReceived(code, arraysize(code));

  tester.FinishStream();
  tester.RunCompilerTasks();
  CHECK(tester.IsPromiseFulfilled());

  // Create an instance.
  auto* i_isolate = CcTest::i_isolate();
  ErrorThrower thrower{i_isolate, "TestMoreFunctionsCanBeSerializedCallback"};
  Handle<WasmInstanceObject> instance =
      GetWasmEngine()
          ->SyncInstantiate(i_isolate, &thrower, tester.module_object(), {}, {})
          .ToHandleChecked();
  CHECK(!thrower.error());

  // Execute the first function 100 times (which triggers tier-up and hence
  // caching).
  Handle<WasmExportedFunction> func_a =
      testing::GetExportedFunction(i_isolate, instance, "a").ToHandleChecked();
  Handle<Object> receiver = ReadOnlyRoots{i_isolate}.undefined_value_handle();
  for (int i = 0; i < 100; ++i) {
    Execution::Call(i_isolate, func_a, receiver, 0, nullptr).Check();
  }

  // Ensure that background compilation is being executed.
  tester.RunCompilerTasks();

  // The caching callback should be called within the next second (be generous).
  CHECK(WaitForCaching(caching_expected_timeout_ms));

  // There should be no other caching happening within the next 20ms.
  CHECK(!WaitForCaching(no_caching_expected_timeout_ms));

  // Now execute the other two functions 100 times and validate that this
  // triggers another event (but not two).
  Handle<WasmExportedFunction> func_b_and_c[]{
      testing::GetExportedFunction(i_isolate, instance, "b").ToHandleChecked(),
      testing::GetExportedFunction(i_isolate, instance, "c").ToHandleChecked()};
  for (int i = 0; i < 100; ++i) {
    for (auto func : func_b_and_c) {
      Execution::Call(i_isolate, func, receiver, 0, nullptr).Check();
    }
  }

  // Ensure that background compilation is being executed.
  tester.RunCompilerTasks();

  // The caching callback should be called within the next second (be generous).
  CHECK(WaitForCaching(caching_expected_timeout_ms));

  // There should be no other caching happening within the next 20ms.
  CHECK(!WaitForCaching(no_caching_expected_timeout_ms));
}

STREAM_TEST(TestHardCachingThreshold) {
  // The "more functions can be serialized" callback will only be triggered with
  // dynamic tiering, so skip this test if dynamic tiering is disabled.
  if (!v8_flags.wasm_dynamic_tiering) return;

  // Reduce the caching threshold to 1 byte and set the hard threshold to 10
  // bytes so that one small function hits both thresholds.
  FlagScope<int> caching_threshold(&v8_flags.wasm_caching_threshold, 1);
  FlagScope<int> caching_hard_threshold(&v8_flags.wasm_caching_hard_threshold,
                                        10);
  // Set a caching timeout such that the hard threshold has any meaning. This
  // timeout should never be reached.
  constexpr int kCachingTimeoutMs = 1000;
  FlagScope<int> caching_timeout(&v8_flags.wasm_caching_timeout_ms,
                                 kCachingTimeoutMs);

  // Use a semaphore to wait for the caching event on the main thread.
  std::atomic<bool> caching_was_triggered{false};
  StreamTester tester(isolate);
  tester.stream()->SetMoreFunctionsCanBeSerializedCallback(
      [&](const std::shared_ptr<NativeModule>& module) {
        caching_was_triggered = true;
      });

  const uint8_t bytes[] = {
      WASM_MODULE_HEADER,  // module header
      SECTION(Type,
              ENTRY_COUNT(1),                      // type count
              SIG_ENTRY_x_x(kI32Code, kI32Code)),  // signature entry
      SECTION(Function, ENTRY_COUNT(1), SIG_INDEX(0)),
      SECTION(Export, ENTRY_COUNT(1),                             // 1 export
              ADD_COUNT('a'), kExternalFunction, FUNC_INDEX(0)),  // "a" (0)
      SECTION(Code,
              U32V_1(1),                              // functions count
              ADD_COUNT(U32V_1(0),                    // locals count
                        kExprLocalGet, 0, kExprEnd))  // body
  };

  tester.OnBytesReceived(bytes, arraysize(bytes));
  tester.FinishStream();
  tester.RunCompilerTasks();
  CHECK(tester.IsPromiseFulfilled());

  CHECK(!caching_was_triggered);

  // Create an instance.
  auto* i_isolate = CcTest::i_isolate();
  ErrorThrower thrower{i_isolate, "TestMoreFunctionsCanBeSerializedCallback"};
  Handle<WasmInstanceObject> instance =
      GetWasmEngine()
          ->SyncInstantiate(i_isolate, &thrower, tester.module_object(), {}, {})
          .ToHandleChecked();
  CHECK(!thrower.error());
  CHECK(!caching_was_triggered);

  // Execute the function 100 times (which triggers tier-up and hence caching).
  Handle<WasmExportedFunction> func_a =
      testing::GetExportedFunction(i_isolate, instance, "a").ToHandleChecked();
  Handle<Object> receiver = ReadOnlyRoots{i_isolate}.undefined_value_handle();
  fo
```