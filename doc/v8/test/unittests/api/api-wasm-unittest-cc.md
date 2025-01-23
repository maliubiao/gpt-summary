Response:
Let's break down the thought process for analyzing the C++ code and generating the response.

1. **Understand the Goal:** The request is to analyze a V8 C++ file (`api-wasm-unittest.cc`) and describe its functionality, relate it to JavaScript if applicable, provide code logic examples, and highlight common programming errors related to the code.

2. **Initial Scan and Keyword Recognition:** Quickly read through the code, looking for key terms:
    * `wasm`:  This is the central theme. The filename itself confirms this.
    * `TestWithIsolate`, `TEST_F`:  Indicates this is a unit test file using Google Test.
    * `WasmStreamingCallback`, `WasmModuleObject`, `WebAssembly`:  These point to specific WebAssembly API interactions.
    * `Promise`:  Suggests asynchronous operations.
    * `Context`, `Isolate`:  Core V8 concepts for execution environments.
    * `RunJS`: Implies executing JavaScript code within the tests.
    * `SetWasmStreamingCallback`, `SetWasmImportedStringsEnabledCallback`, `SetWasmJSPIEnabledCallback`:  These are V8 API functions for customizing WASM behavior.
    * `kMinimalWasmModuleBytes`: A literal representing a simple WASM module.

3. **Identify the Core Functionality:** Based on the keywords and the structure of the tests, it's clear the file focuses on testing the V8 C++ API related to WebAssembly. Specifically, it seems to cover:
    * **Streaming Compilation:**  The `WasmStreamingCallback` and related tests are a major focus.
    * **Module Compilation:** The `WasmCompileToWasmModuleObject` test directly addresses this.
    * **Error Handling:** The `WasmErrorIsSharedCrossOrigin` test checks how WASM errors are reported.
    * **Experimental Features:** The tests involving `WasmEnableDisableImportedStrings` and `WasmEnableDisableJSPI`/`WasmInstallJSPI` deal with enabling and controlling experimental WASM features.

4. **Analyze Individual Tests:**  Go through each `TEST_F` block and understand its purpose:
    * **`WasmStreamingCallback`:** Verifies that the `WasmStreamingCallback` set by the embedder is actually called. It also checks for proper cleanup of data using weak handles and garbage collection.
    * **`WasmStreamingOnBytesReceived`:** Tests the `OnBytesReceived` callback of the `WasmStreaming` API, simulating receiving bytes of the WASM module incrementally.
    * **`WasmStreamingFinishWithSuccess`:** Simulates a successful streaming compilation.
    * **`WasmStreamingFinishWithFailure`:** Simulates a failed streaming compilation without providing any data.
    * **`WasmStreamingAbortWithReject`:** Simulates aborting streaming compilation and checks if the promise is rejected.
    * **`WasmStreamingAbortWithoutReject`:**  Simulates aborting without a rejection (likely an early abort).
    * **`WasmCompileToWasmModuleObject`:**  Tests the direct compilation of a WASM module from bytes.
    * **`WasmStreamingSetCallback`:** Checks if a callback for when more functions can be serialized is correctly set.
    * **`WasmErrorIsSharedCrossOrigin`:**  Examines the properties of a WASM runtime error, specifically that it's flagged as cross-origin.
    * **`WasmEnableDisableImportedStrings`:**  Tests the API for controlling the `imported_strings` WASM feature via both a flag and a callback.
    * **`WasmEnableDisableJSPI`:** Tests the API for requesting the `jspi` (JavaScript Promise Integration) WASM feature.
    * **`WasmInstallJSPI`:** Tests the actual installation of the JSPI feature.

5. **Relate to JavaScript:** Identify how the tested C++ APIs correspond to JavaScript WebAssembly APIs:
    * `WebAssembly.compileStreaming()`: Directly relates to the `WasmStreamingCallback` tests.
    * `WebAssembly.Module()`:  Corresponds to `WasmModuleObject::Compile()`.
    * The error handling in `WasmErrorIsSharedCrossOrigin` relates to how JavaScript catches WASM errors.
    * The imported strings and JSPI features are controlled through browser/embedder settings or APIs, not directly through standard JavaScript, but they affect the behavior of `WebAssembly.Module` and `WebAssembly.Instance`.

6. **Provide JavaScript Examples:** Create simple JavaScript snippets to illustrate the C++ test scenarios. Focus on the core concepts being tested.

7. **Infer Code Logic and Provide Examples:** For tests involving conditional behavior or data manipulation, create hypothetical input and output scenarios. For example, the streaming tests have implicit logic: providing valid WASM bytes should lead to success, while not providing enough or aborting should lead to failure or pending states.

8. **Identify Common Programming Errors:** Think about the potential mistakes developers might make when using these APIs:
    * Incorrectly handling the `WasmStreamingCallback`.
    * Not providing valid WASM bytes during streaming.
    * Misunderstanding the asynchronous nature of streaming compilation.
    * Expecting synchronous behavior where it doesn't exist.
    * Incorrectly managing the lifetime of objects passed to callbacks.

9. **Structure the Response:** Organize the information logically with clear headings and bullet points. Start with a general summary, then detail each aspect requested in the prompt.

10. **Review and Refine:**  Read through the generated response to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where more detail might be needed. For example, initially, I might just say "tests streaming," but refining it to "tests the V8 C++ API for WebAssembly streaming compilation" is more precise. Similarly, instead of just saying "tests module compilation," specifying the API function `WasmModuleObject::Compile` adds valuable detail.

This iterative process of scanning, identifying core functionalities, analyzing individual tests, relating to JavaScript, and then elaborating with examples and common errors allows for a comprehensive understanding and explanation of the given C++ code.
`v8/test/unittests/api/api-wasm-unittest.cc` 是一个 V8 JavaScript 引擎的 C++ 单元测试文件，专门用于测试 V8 引擎中与 WebAssembly (Wasm) API 相关的 C++ 接口功能。

**功能列表:**

这个文件包含了多个独立的测试用例 (使用 `TEST_F` 宏定义)，每个测试用例针对 V8 的 WebAssembly API 的不同方面进行验证。主要功能可以归纳为以下几点：

1. **`WasmStreamingCallback` 测试:**
   - 测试设置 `WasmStreamingCallback` (一个允许嵌入器在 WASM 模块流式编译过程中接收通知的回调函数) 的功能。
   - 验证当调用 `WebAssembly.compileStreaming` 时，该回调函数是否被正确调用。
   - 检查与回调函数关联的数据是否在不再需要时被正确回收（通过弱引用和垃圾回收）。

2. **`WasmStreamingOnBytesReceived` 测试:**
   - 测试 `WasmStreaming::OnBytesReceived` 方法，该方法用于向流式编译过程提供 WASM 模块的字节数据。
   - 验证在调用 `WebAssembly.compileStreaming` 后，可以通过 `OnBytesReceived` 方法逐步提供模块字节。

3. **`WasmStreamingFinishWithSuccess` 测试:**
   - 测试 `WasmStreaming::Finish` 方法，该方法用于通知流式编译过程已接收到所有字节，并期望编译成功。
   - 验证当提供完整的有效 WASM 模块字节并调用 `Finish` 后，`WebAssembly.compileStreaming` 返回的 Promise 状态变为 `fulfilled`。

4. **`WasmStreamingFinishWithFailure` 测试:**
   - 测试 `WasmStreaming::Finish` 方法在未提供有效 WASM 模块字节的情况下的行为。
   - 验证在这种情况下，`WebAssembly.compileStreaming` 返回的 Promise 状态变为 `rejected`。

5. **`WasmStreamingAbortWithReject` 测试:**
   - 测试 `WasmStreaming::Abort` 方法，该方法用于取消流式编译过程，并带有一个拒绝原因。
   - 验证当调用 `Abort` 并提供拒绝原因时，`WebAssembly.compileStreaming` 返回的 Promise 状态变为 `rejected`。

6. **`WasmStreamingAbortWithoutReject` 测试:**
   - 测试 `WasmStreaming::Abort` 方法，在不提供拒绝原因的情况下取消流式编译过程。
   - 验证在这种情况下，`WebAssembly.compileStreaming` 返回的 Promise 状态保持 `pending`。

7. **`WasmCompileToWasmModuleObject` 测试:**
   - 测试 `WasmModuleObject::Compile` 静态方法，该方法用于从字节数组同步编译 WASM 模块。
   - 验证可以使用此方法成功编译一个简单的 WASM 模块。

8. **`WasmStreamingSetCallback` 测试:**
   - 测试 `WasmStreaming::SetMoreFunctionsCanBeSerializedCallback` 方法，该方法允许设置一个回调函数，当可以序列化更多 WASM 函数时被调用。

9. **`WasmErrorIsSharedCrossOrigin` 测试:**
   - 测试当 WASM 模块运行时发生错误时，错误消息是否被标记为跨域共享 (`IsSharedCrossOrigin`)。
   - 这对于出于安全原因区分来自不同源的错误非常重要。

10. **`WasmEnableDisableImportedStrings` 测试:**
    - 测试启用和禁用 WASM 导入字符串 (imported strings) 的功能，这是一个实验性特性。
    - 验证可以通过标志 (`experimental_wasm_imported_strings`) 和回调函数 (`SetWasmImportedStringsEnabledCallback`) 来控制此特性。

11. **`WasmEnableDisableJSPI` 测试:**
    - 测试启用和禁用 WASM JavaScript Promise Integration (JSPI) 的请求功能。
    - 验证可以通过标志 (`experimental_wasm_jspi`) 和回调函数 (`SetWasmJSPIEnabledCallback`) 来控制是否请求此特性。

12. **`WasmInstallJSPI` 测试:**
    - 测试实际安装 WASM JSPI 特性的功能。
    - 验证在请求 JSPI 后，调用 `WasmJs::InstallConditionalFeatures` 可以启用该特性。

**关于文件后缀 `.tq`:**

如果 `v8/test/unittests/api/api-wasm-unittest.cc` 以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。Torque 是 V8 用来定义其内置函数和类型系统的领域特定语言。然而，根据你提供的文件名，它以 `.cc` 结尾，因此是一个标准的 C++ 文件。

**与 JavaScript 的关系和示例:**

这个 C++ 测试文件直接测试了与 WebAssembly JavaScript API 相关的 V8 内部实现。以下是一些 JavaScript 示例，展示了这些 C++ 测试覆盖的功能：

1. **`WebAssembly.compileStreaming()`:** 对应于 `WasmStreamingCallback` 和其他 `WasmStreaming` 相关的测试。

   ```javascript
   fetch('module.wasm')
     .then(response => WebAssembly.compileStreaming(response))
     .then(module => {
       console.log("WASM module compiled successfully:", module);
     })
     .catch(error => {
       console.error("Failed to compile WASM module:", error);
     });
   ```

2. **`WebAssembly.Module()`:** 对应于 `WasmCompileToWasmModuleObject` 测试。

   ```javascript
   const wasmBytes = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
   const module = new WebAssembly.Module(wasmBytes);
   console.log("WASM module created:", module);
   ```

3. **WASM 运行时错误:** 对应于 `WasmErrorIsSharedCrossOrigin` 测试。

   ```javascript
   const wasmBytes = new Uint8Array(/* ... 包含运行时错误的 WASM 字节 ... */);
   const module = new WebAssembly.Module(wasmBytes);
   const instance = new WebAssembly.Instance(module);
   try {
     instance.exports.someFunction();
   } catch (error) {
     console.error("WASM runtime error:", error);
     // 检查 error 对象是否包含跨域信息 (但 JavaScript API 中不直接暴露 IsSharedCrossOrigin)
   }
   ```

**代码逻辑推理和假设输入/输出:**

以 `WasmStreamingFinishWithSuccess` 测试为例：

**假设输入:**

- `WasmStreamingCallback` 设置为一个可以访问 `WasmStreaming` 对象的函数。
- 调用 `WebAssembly.compileStreaming(null)` (参数在此测试中不重要)。
- 在回调函数中，调用 `streaming->OnBytesReceived` 提供 `kMinimalWasmModuleBytes`。
- 随后调用 `streaming->Finish()`。

**预期输出:**

- `WebAssembly.compileStreaming` 返回的 Promise 的状态最终变为 `Promise::kFulfilled` (已完成)。

**用户常见的编程错误示例:**

1. **在流式编译中提供不完整的或无效的 WASM 字节:**

   ```javascript
   fetch('module.wasm')
     .then(response => {
       const reader = response.body.getReader();
       const streaming = WebAssembly.compileStreaming(Promise.resolve(response)); // 正确的方式

       reader.read().then(({ done, value }) => {
         // 错误：假设只读取一部分数据就完成
         if (value) {
           // ... 处理部分数据 ...
         }
         // 错误地认为编译会成功
       });
     });
   ```
   **C++ 对应的测试:** `WasmStreamingFinishWithFailure` 模拟了这种情况。

2. **忘记调用 `streaming->Finish()` 或 `streaming->Abort()`:**

   嵌入器实现了 `WasmStreamingCallback`，但忘记在接收到所有数据后调用 `Finish`，或者在发生错误时调用 `Abort`。这将导致 Promise 永远处于 `pending` 状态。

   ```c++
   void MyWasmStreamingCallback(const FunctionCallbackInfo<Value>& info) {
     // ... 获取 WasmStreaming 对象 ...
     // 错误：忘记调用 streaming->Finish() 或 streaming->Abort()
   }
   ```
   **C++ 对应的测试:**  虽然没有直接测试忘记调用的情况，但 `WasmStreamingFinishWithSuccess` 和 `WasmStreamingAbortWithReject/WithoutReject` 都强调了这些调用的重要性。

3. **在设置 `WasmStreamingCallback` 之前调用 `WebAssembly.compileStreaming`:**

   如果嵌入器没有先设置回调函数，V8 将无法通知嵌入器流式编译过程的状态。

   ```javascript
   // 错误：在设置回调之前调用
   WebAssembly.compileStreaming(fetch('module.wasm'));

   isolate->SetWasmStreamingCallback(/* ... */);
   ```

总而言之，`v8/test/unittests/api/api-wasm-unittest.cc` 是一个关键的测试文件，用于确保 V8 的 WebAssembly C++ API 按照预期工作，并且能够正确地与 JavaScript WebAssembly API 进行交互。它覆盖了流式编译、模块编译、错误处理以及一些实验性特性。

### 提示词
```
这是目录为v8/test/unittests/api/api-wasm-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/api/api-wasm-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "include/v8-context.h"
#include "include/v8-function-callback.h"
#include "include/v8-local-handle.h"
#include "include/v8-object.h"
#include "include/v8-persistent-handle.h"
#include "include/v8-promise.h"
#include "include/v8-wasm.h"
#include "src/api/api-inl.h"
#include "src/handles/global-handles.h"
#include "src/wasm/wasm-features.h"
#include "src/wasm/wasm-js.h"
#include "test/common/flag-utils.h"
#include "test/unittests/heap/heap-utils.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {

bool wasm_streaming_callback_got_called = false;
bool wasm_streaming_data_got_collected = false;

// The bytes of a minimal WebAssembly module.
const uint8_t kMinimalWasmModuleBytes[]{0x00, 0x61, 0x73, 0x6d,
                                        0x01, 0x00, 0x00, 0x00};

class ApiWasmTest : public TestWithIsolate {
 public:
  void TestWasmStreaming(WasmStreamingCallback callback,
                         Promise::PromiseState expected_state) {
    isolate()->SetWasmStreamingCallback(callback);
    HandleScope scope(isolate());

    Local<Context> context = Context::New(isolate());
    Context::Scope context_scope(context);
    // Call {WebAssembly.compileStreaming} with {null} as parameter. The
    // parameter is only really processed by the embedder, so for this test the
    // value is irrelevant.
    Local<Promise> promise =
        Local<Promise>::Cast(RunJS("WebAssembly.compileStreaming(null)"));
    EmptyMessageQueues();
    CHECK_EQ(expected_state, promise->State());
  }
};

void WasmStreamingTestFinalizer(const WeakCallbackInfo<void>& data) {
  CHECK(!wasm_streaming_data_got_collected);
  wasm_streaming_data_got_collected = true;
  i::GlobalHandles::Destroy(reinterpret_cast<i::Address*>(data.GetParameter()));
}

void WasmStreamingCallbackTestCallbackIsCalled(
    const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(!wasm_streaming_callback_got_called);
  wasm_streaming_callback_got_called = true;

  i::Handle<i::Object> global_handle =
      reinterpret_cast<i::Isolate*>(info.GetIsolate())
          ->global_handles()
          ->Create(*Utils::OpenDirectHandle(*info.Data()));
  i::GlobalHandles::MakeWeak(global_handle.location(), global_handle.location(),
                             WasmStreamingTestFinalizer,
                             WeakCallbackType::kParameter);
}

void WasmStreamingCallbackTestFinishWithSuccess(
    const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  std::shared_ptr<WasmStreaming> streaming =
      WasmStreaming::Unpack(info.GetIsolate(), info.Data());
  streaming->OnBytesReceived(kMinimalWasmModuleBytes,
                             arraysize(kMinimalWasmModuleBytes));
  streaming->Finish();
}

void WasmStreamingCallbackTestFinishWithFailure(
    const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  std::shared_ptr<WasmStreaming> streaming =
      WasmStreaming::Unpack(info.GetIsolate(), info.Data());
  streaming->Finish();
}

void WasmStreamingCallbackTestAbortWithReject(
    const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  std::shared_ptr<WasmStreaming> streaming =
      WasmStreaming::Unpack(info.GetIsolate(), info.Data());
  streaming->Abort(Object::New(info.GetIsolate()));
}

void WasmStreamingCallbackTestAbortNoReject(
    const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  std::shared_ptr<WasmStreaming> streaming =
      WasmStreaming::Unpack(info.GetIsolate(), info.Data());
  streaming->Abort({});
}

void WasmStreamingCallbackTestOnBytesReceived(
    const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  std::shared_ptr<WasmStreaming> streaming =
      WasmStreaming::Unpack(info.GetIsolate(), info.Data());

  // The first bytes of the WebAssembly magic word.
  const uint8_t bytes[]{0x00, 0x61, 0x73};
  streaming->OnBytesReceived(bytes, arraysize(bytes));
}

void WasmStreamingMoreFunctionsCanBeSerializedCallback(
    const FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  std::shared_ptr<WasmStreaming> streaming =
      WasmStreaming::Unpack(info.GetIsolate(), info.Data());
  streaming->SetMoreFunctionsCanBeSerializedCallback([](CompiledWasmModule) {});
}

TEST_F(ApiWasmTest, WasmStreamingCallback) {
  TestWasmStreaming(WasmStreamingCallbackTestCallbackIsCalled,
                    Promise::kPending);
  CHECK(wasm_streaming_callback_got_called);
  InvokeMemoryReducingMajorGCs(i_isolate());
  CHECK(wasm_streaming_data_got_collected);
}

TEST_F(ApiWasmTest, WasmStreamingOnBytesReceived) {
  TestWasmStreaming(WasmStreamingCallbackTestOnBytesReceived,
                    Promise::kPending);
}

TEST_F(ApiWasmTest, WasmStreamingFinishWithSuccess) {
  TestWasmStreaming(WasmStreamingCallbackTestFinishWithSuccess,
                    Promise::kFulfilled);
}

TEST_F(ApiWasmTest, WasmStreamingFinishWithFailure) {
  TestWasmStreaming(WasmStreamingCallbackTestFinishWithFailure,
                    Promise::kRejected);
}

TEST_F(ApiWasmTest, WasmStreamingAbortWithReject) {
  TestWasmStreaming(WasmStreamingCallbackTestAbortWithReject,
                    Promise::kRejected);
}

TEST_F(ApiWasmTest, WasmStreamingAbortWithoutReject) {
  TestWasmStreaming(WasmStreamingCallbackTestAbortNoReject, Promise::kPending);
}

TEST_F(ApiWasmTest, WasmCompileToWasmModuleObject) {
  Local<Context> context = Context::New(isolate());
  Context::Scope context_scope(context);
  auto maybe_module = WasmModuleObject::Compile(
      isolate(), {kMinimalWasmModuleBytes, arraysize(kMinimalWasmModuleBytes)});
  CHECK(!maybe_module.IsEmpty());
}

TEST_F(ApiWasmTest, WasmStreamingSetCallback) {
  TestWasmStreaming(WasmStreamingMoreFunctionsCanBeSerializedCallback,
                    Promise::kPending);
}

TEST_F(ApiWasmTest, WasmErrorIsSharedCrossOrigin) {
  Isolate::Scope iscope(isolate());
  HandleScope scope(isolate());
  Local<Context> context = Context::New(isolate());
  Context::Scope cscope(context);

  TryCatch try_catch(isolate());
  // A fairly minimal Wasm module that produces an error at runtime:
  // it returns {null} from an imported function that's typed to return
  // a non-null reference.
  const char* expected_message =
      "Uncaught TypeError: type incompatibility when transforming from/to JS";
  const char* src =
      "let raw = new Uint8Array(["
      "  0x00, 0x61, 0x73, 0x6d,  // wasm magic                            \n"
      "  0x01, 0x00, 0x00, 0x00,  // wasm version                          \n"

      "  0x01, 0x06,              // Type section, length 6                \n"
      "  0x01, 0x60,              // 1 type, kind: func                    \n"
      "  0x00, 0x01, 0x64, 0x6f,  // 0 params, 1 result: (ref extern)      \n"

      "  0x02, 0x07, 0x01,        // Import section, length 7, 1 import    \n"
      "  0x01, 0x6d, 0x01, 0x6e,  // 'm' 'n'                               \n"
      "  0x00, 0x00,              // kind: function $type0                 \n"

      "  0x03, 0x02,              // Function section, length 2            \n"
      "  0x01, 0x00,              // 1 function, $type0                    \n"

      "  0x07, 0x05, 0x01,        // Export section, length 5, 1 export    \n"
      "  0x01, 0x66, 0x00, 0x01,  // 'f': function #1                      \n"

      "  0x0a, 0x06, 0x01,        // Code section, length 6, 1 function    \n"
      "  0x04, 0x00,              // body size 4, 0 locals                 \n"
      "  0x10, 0x00, 0x0b,        // call $m.n; end                        \n"
      "]);                                                                 \n"

      "let mod = new WebAssembly.Module(raw.buffer);                       \n"
      "let instance = new WebAssembly.Instance(mod, {m: {n: () => null}}); \n"
      "instance.exports.f();";

  TryRunJS(src);
  EXPECT_TRUE(try_catch.HasCaught());
  Local<Message> message = try_catch.Message();
  CHECK_EQ(0, strcmp(*String::Utf8Value(isolate(), message->Get()),
                     expected_message));
  EXPECT_TRUE(message->IsSharedCrossOrigin());
}

TEST_F(ApiWasmTest, WasmEnableDisableImportedStrings) {
  Local<Context> context_local = Context::New(isolate());
  Context::Scope context_scope(context_local);
  i::Handle<i::NativeContext> context = v8::Utils::OpenHandle(*context_local);
  // Test enabling/disabling via flag.
  {
    i::FlagScope<bool> flag_strings(
        &i::v8_flags.experimental_wasm_imported_strings, true);
    EXPECT_TRUE(i_isolate()->IsWasmImportedStringsEnabled(context));

    // When flag is on, callback return value has no effect.
    isolate()->SetWasmImportedStringsEnabledCallback([](auto) { return true; });
    EXPECT_TRUE(i_isolate()->IsWasmImportedStringsEnabled(context));
    EXPECT_TRUE(i::wasm::WasmEnabledFeatures::FromIsolate(i_isolate())
                    .has_imported_strings());
    isolate()->SetWasmImportedStringsEnabledCallback(
        [](auto) { return false; });
    EXPECT_TRUE(i_isolate()->IsWasmImportedStringsEnabled(context));
    EXPECT_TRUE(i::wasm::WasmEnabledFeatures::FromIsolate(i_isolate())
                    .has_imported_strings());
  }
  {
    i::FlagScope<bool> flag_strings(
        &i::v8_flags.experimental_wasm_imported_strings, false);
    EXPECT_FALSE(i_isolate()->IsWasmImportedStringsEnabled(context));

    // Test enabling/disabling via callback.
    isolate()->SetWasmImportedStringsEnabledCallback([](auto) { return true; });
    EXPECT_TRUE(i_isolate()->IsWasmImportedStringsEnabled(context));
    EXPECT_TRUE(i::wasm::WasmEnabledFeatures::FromIsolate(i_isolate())
                    .has_imported_strings());
    isolate()->SetWasmImportedStringsEnabledCallback(
        [](auto) { return false; });
    EXPECT_FALSE(i_isolate()->IsWasmImportedStringsEnabled(context));
    EXPECT_FALSE(i::wasm::WasmEnabledFeatures::FromIsolate(i_isolate())
                     .has_imported_strings());
  }
}

TEST_F(ApiWasmTest, WasmEnableDisableJSPI) {
  Local<Context> context_local = Context::New(isolate());
  Context::Scope context_scope(context_local);
  i::Handle<i::NativeContext> context = v8::Utils::OpenHandle(*context_local);
  // Test enabling/disabling via flag.
  {
    i::FlagScope<bool> flag_strings(&i::v8_flags.experimental_wasm_jspi, true);
    EXPECT_TRUE(i_isolate()->IsWasmJSPIRequested(context));
  }
  {
    i::FlagScope<bool> flag_strings(&i::v8_flags.experimental_wasm_jspi, false);
    EXPECT_FALSE(i_isolate()->IsWasmJSPIRequested(context));
  }
  // Test enabling/disabling via callback.
  isolate()->SetWasmJSPIEnabledCallback([](auto) { return true; });
  EXPECT_TRUE(i_isolate()->IsWasmJSPIRequested(context));
  isolate()->SetWasmJSPIEnabledCallback([](auto) { return false; });
  EXPECT_FALSE(i_isolate()->IsWasmJSPIRequested(context));
}

TEST_F(ApiWasmTest, WasmInstallJSPI) {
  Local<Context> context_local = Context::New(isolate());
  Context::Scope context_scope(context_local);
  i::Handle<i::NativeContext> context = v8::Utils::OpenHandle(*context_local);

  EXPECT_FALSE(i_isolate()->IsWasmJSPIEnabled(context));
  i::wasm::WasmEnabledFeatures features =
      i::wasm::WasmEnabledFeatures::FromIsolate(i_isolate());
  EXPECT_FALSE(features.has_jspi());

  // Test installing JSPI via flag.
  isolate()->SetWasmJSPIEnabledCallback([](auto) { return true; });

  EXPECT_TRUE(i_isolate()->IsWasmJSPIRequested(context));
  EXPECT_FALSE(i_isolate()->IsWasmJSPIEnabled(context));
  features = i::wasm::WasmEnabledFeatures::FromIsolate(i_isolate());
  EXPECT_FALSE(features.has_jspi());

  i::WasmJs::InstallConditionalFeatures(i_isolate(), context);

  EXPECT_TRUE(i_isolate()->IsWasmJSPIEnabled(context));
  features = i::wasm::WasmEnabledFeatures::FromIsolate(i_isolate());
  EXPECT_TRUE(features.has_jspi());
}

}  // namespace v8
```