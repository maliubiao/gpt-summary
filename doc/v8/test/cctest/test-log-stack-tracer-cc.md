Response:
Let's break down the thought process for analyzing the C++ code and answering the request.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `v8/test/cctest/test-log-stack-tracer.cc`. The request also specifically asks about connections to Torque, JavaScript, code logic, and common programming errors.

**2. Initial Code Scan and Keyword Spotting:**

I'd start by quickly scanning the code, looking for familiar keywords and patterns related to V8 testing and stack tracing. Some key observations:

* **Copyright and License:** Standard header, indicating V8 project.
* **Includes:**  `v8-function.h`, `api-inl.h`, `strings.h`, `frames.h`, `isolate.h`, `objects-inl.h`, `tick-sample.h`, `cctest.h`, `trace-extension.h`. These headers strongly suggest the code is related to V8 internals, particularly execution, object representation, and profiling (tick sampling). The `trace-extension.h` is a big clue about its purpose.
* **Namespaces:** `v8::internal`. This reinforces that it's about V8's internal workings, not the public API.
* **Helper Functions:**  `IsAddressWithinFuncCode`. This clearly points to checking if a given memory address falls within the code range of a JavaScript function. This is crucial for stack tracing verification.
* **`construct_call` Function:** This is a C++ function called as a constructor. It manipulates stack frames (`StackFrameIterator`) and extracts frame pointer information. The logic related to 32-bit and 64-bit architectures is also important.
* **`CreateFramePointerGrabberConstructor`:**  This function uses the V8 API to create a JavaScript constructor that wraps the `construct_call` C++ function. This establishes a bridge between C++ and JavaScript for stack frame inspection.
* **`CreateTraceCallerFunction`:** This function dynamically generates JavaScript code that uses the `FPGrabber` constructor to get the frame pointer and then calls a tracing function (presumably defined in the `trace-extension`).
* **`TEST(...)` Macros:** These clearly indicate that the file contains unit tests using V8's internal testing framework (`cctest`).
* **Test Names:** `CFromJSStackTrace`, `PureJSStackTrace`, `PureCStackTrace`, `JsEntrySp`. These names strongly suggest the scenarios being tested: stack tracing initiated from C++ called by JavaScript, stack tracing in pure JavaScript (emulated), stack tracing in pure C++, and something related to the "JS entry SP" (Stack Pointer).

**3. Deeper Dive into Key Functions and Tests:**

* **`construct_call`:**  The logic here is about navigating the stack frames when a constructor is called. The checks (`CHECK(...)`) are assertions to validate the expected stack frame types. The extraction of the frame pointer and its encoding into `low_bits` and `high_bits` (for 64-bit) are vital for transferring this information back to JavaScript.
* **`CreateTraceCallerFunction`:**  The string formatting (`v8::base::SNPrintF`) to create the JavaScript function dynamically is interesting. It ties the C++ frame pointer grabbing mechanism to a JavaScript function that will call the `trace` or `js_trace` extension functions.
* **`CFromJSStackTrace`:** This test sets `turbo_inlining` to `false`, implying that inlining might interfere with the test's correctness. It then defines JavaScript functions (`JSFuncDoTrace`, `JSTrace`) that orchestrate the call from JavaScript to the C++ tracing extension. The assertions at the end verify that the captured stack frames correspond to the expected JavaScript functions.
* **`PureJSStackTrace`:**  Similar to `CFromJSStackTrace`, but it uses `js_trace` and aims to simulate a pure JavaScript stack trace. The comment about erasing `Isolate::c_entry_fp` is a crucial detail, indicating a workaround for testing purely within the JS context.
* **`PureCStackTrace`:** This test calls a recursive C++ function (`CFunc`) and triggers the tracing mechanism. The comment clarifies that it's checking for crashes, as meaningful information from pure C++ stack unwinding within V8's JS stack tracing isn't expected.
* **`JsEntrySp`:** This test seems to be checking the behavior of functions named `js_entry_sp` and `js_entry_sp_level2`. The assertions check if `TraceExtension::GetJsEntrySp()` returns a value before and after calling these JavaScript functions.

**4. Connecting to the Request's Specific Points:**

* **Functionality:** Based on the above analysis, the primary function is to **test the V8 stack tracing mechanism** in different scenarios: when called from C++ triggered by JavaScript, within pure JavaScript, and within pure C++.
* **Torque:**  The file extension `.cc` is a strong indicator that it's **not a Torque file**. Torque files use `.tq`.
* **JavaScript Relationship:**  There's a **strong relationship**. The tests involve executing JavaScript code to trigger the stack tracing and then verifying the captured stack frames. The `CreateFramePointerGrabberConstructor` and `CreateTraceCallerFunction` directly generate and execute JavaScript.
* **JavaScript Example:**  I'd construct an example based on the code, showcasing how the frame pointer is captured and used.
* **Code Logic Inference:**  I'd focus on the stack frame traversal logic in `construct_call` and how the frame pointer is being extracted and passed. The conditional logic for 32-bit and 64-bit architectures is important here. I would hypothesize input (a function call) and the expected output (the captured frame pointers).
* **Common Programming Errors:**  I'd consider errors related to stack overflow (although not directly tested here, the concept of stack frames is relevant), incorrect function calls (leading to unexpected stack frames), and potential issues with platform-specific code (like the 32/64-bit handling).

**5. Structuring the Answer:**

Finally, I'd organize the findings into a clear and structured answer, addressing each point of the request. Using headings and bullet points helps readability. I'd start with a high-level summary of the file's purpose and then delve into the specifics.

This step-by-step process, combining code scanning, keyword spotting, deeper analysis of key functions, and connecting back to the specific requirements of the request, allows for a comprehensive and accurate understanding of the code.
`v8/test/cctest/test-log-stack-tracer.cc` 是一个 V8 源代码文件，其主要功能是 **测试 V8 引擎的堆栈跟踪（stack tracing）机制**。它验证了在不同场景下，V8 的堆栈跟踪功能是否能够正确地捕获和记录函数调用栈的信息。

以下是该文件的具体功能点：

1. **测试从 C++ 代码中由 JavaScript 调用的堆栈跟踪：**
   - 它模拟了 JavaScript 代码调用原生 C++ 函数的情况。
   - 使用 `TickSample::Trace` 函数来触发堆栈跟踪。
   - 验证了在原生函数执行期间，堆栈跟踪能够正确地回溯到 JavaScript 代码的调用栈。

2. **测试纯 JavaScript 代码的堆栈跟踪：**
   - 它模拟了完全在 JavaScript 环境中执行代码时的堆栈跟踪。
   - 通过设置特定的条件（例如，清除 `Isolate::c_entry_fp`），强制 `TickSample::Trace` 使用传入的帧指针作为起始点。
   - 验证了在纯 JavaScript 执行期间，堆栈跟踪能够正确地捕获 JavaScript 函数的调用关系。

3. **测试纯 C++ 代码的堆栈跟踪（主要用于防止崩溃）：**
   - 它直接在 C++ 代码中调用会触发堆栈跟踪的函数。
   - 由于 `TickSample::Trace` 主要用于展开 JavaScript 代码，因此在这种情况下，它可能无法获取有意义的 JavaScript 信息。
   - 该测试的主要目的是确保在纯 C++ 环境下调用堆栈跟踪相关函数不会导致程序崩溃。

4. **测试 `js_entry_sp` 相关功能：**
   - 它测试了与 JavaScript 入口栈指针 (`js_entry_sp`) 相关的扩展功能。
   - 验证了在执行 JavaScript 代码前后，以及调用特定的 JavaScript 函数后，`TraceExtension::GetJsEntrySp()` 的返回值是否符合预期。

**关于文件扩展名和 Torque：**

`v8/test/cctest/test-log-stack-tracer.cc` 的文件扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**。如果文件名以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。

**与 JavaScript 功能的关系以及示例：**

该文件与 JavaScript 功能有密切关系，因为它主要测试 V8 引擎在执行 JavaScript 代码时的堆栈跟踪能力。

**JavaScript 示例：**

```javascript
function functionA() {
  functionB();
}

function functionB() {
  // 假设在这里触发了堆栈跟踪
  debugger; // 可以使用 debugger 语句来暂停执行，并查看调用栈
}

functionA();
```

在这个例子中，当执行到 `debugger` 语句时，V8 引擎会暂停执行，并且开发者可以查看当前的调用栈，看到 `functionB` 被 `functionA` 调用。`test-log-stack-tracer.cc` 中的测试就是为了验证 V8 引擎在内部能够正确地记录和表示这种调用关系。

**代码逻辑推理和假设输入/输出：**

让我们以 `CFromJSStackTrace` 测试为例进行代码逻辑推理：

**假设输入：**

1. 执行以下 JavaScript 代码：
   ```javascript
   function JSTrace() {
     JSFuncDoTrace();
   }
   JSTrace();
   ```
2. `JSFuncDoTrace` 函数在内部调用了一个 C++ 扩展函数 `trace`，该函数会触发 `TickSample::Trace`。

**代码逻辑：**

1. `JSFuncDoTrace` 函数执行，它会创建一个 `FPGrabber` 对象。
2. `FPGrabber` 的构造函数（C++ 函数 `construct_call`）会被调用。
3. `construct_call` 函数会遍历当前的栈帧，找到调用 `JSFuncDoTrace` 的 JavaScript 函数的帧指针。
4. 帧指针的低位和高位（如果是 64 位架构）会被存储在 `FPGrabber` 对象的属性 `low_bits` 和 `high_bits` 中。
5. `JSFuncDoTrace` 函数调用 C++ 扩展函数 `trace`，并将 `fp.low_bits` 和 `fp.high_bits` 作为参数传递。
6. C++ 扩展函数 `trace` 内部会调用 `TickSample::Trace`，并使用接收到的帧指针信息进行堆栈回溯。

**预期输出：**

`sample.stack` 数组中应该包含指向 `JSFuncDoTrace` 和 `JSTrace` 函数代码的地址。`sample.has_external_callback` 应该为 `true`，并且 `sample.external_callback_entry` 应该指向 `i::TraceExtension::Trace` 函数的地址。

**用户常见的编程错误示例：**

虽然此代码文件本身是测试代码，但它所测试的功能与以下用户编程错误有关：

1. **栈溢出（Stack Overflow）：**  当函数调用层级过深，导致调用栈超出预分配的大小时，会发生栈溢出。堆栈跟踪功能可以帮助开发者定位导致栈溢出的函数调用链。

   ```javascript
   function recursiveFunction() {
     recursiveFunction(); // 没有终止条件的递归调用
   }
   recursiveFunction(); // 可能会导致栈溢出
   ```

2. **异步操作中的上下文丢失：** 在异步编程中，如果错误地处理了 `this` 上下文或闭包，可能会导致错误发生的位置难以追踪。堆栈跟踪可以帮助理解异步操作执行时的调用关系。

   ```javascript
   function fetchData(callback) {
     setTimeout(function() {
       console.log(this); // 这里的 this 可能不是期望的对象
       callback(null, "data");
     }, 100);
   }

   const myObject = {
     processData: function() {
       fetchData(function(err, data) {
         console.log(this); // 这里的 this 指向 window 或 undefined
         // ... 访问 myObject 的属性可能会出错
       });
     }
   };

   myObject.processData();
   ```

3. **未捕获的异常：** 当 JavaScript 代码抛出异常但没有被 `try...catch` 块捕获时，V8 引擎会提供堆栈跟踪信息，帮助开发者定位异常发生的位置和原因。

   ```javascript
   function divide(a, b) {
     if (b === 0) {
       throw new Error("除数不能为零");
     }
     return a / b;
   }

   function calculate() {
     const result = divide(10, 0); // 这里会抛出异常
     console.log(result);
   }

   calculate(); // 引擎会输出未捕获异常的堆栈跟踪信息
   ```

总而言之，`v8/test/cctest/test-log-stack-tracer.cc` 是一个关键的测试文件，用于确保 V8 引擎的堆栈跟踪功能在各种场景下都能正常工作，这对于调试 JavaScript 代码和理解程序执行流程至关重要。

Prompt: 
```
这是目录为v8/test/cctest/test-log-stack-tracer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-log-stack-tracer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2011 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Tests of profiler-related functions from log.h

#include <stdlib.h>

#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "src/base/strings.h"
#include "src/execution/frames.h"
#include "src/execution/isolate.h"
#include "src/execution/vm-state-inl.h"
#include "src/objects/objects-inl.h"
#include "src/profiler/tick-sample.h"
#include "test/cctest/cctest.h"
#include "test/cctest/trace-extension.h"

namespace v8 {
namespace internal {

static bool IsAddressWithinFuncCode(Tagged<JSFunction> function,
                                    Isolate* isolate, void* addr) {
  i::Tagged<i::AbstractCode> code = function->abstract_code(isolate);
  return code->contains(isolate, reinterpret_cast<Address>(addr));
}

static bool IsAddressWithinFuncCode(v8::Local<v8::Context> context,
                                    Isolate* isolate, const char* func_name,
                                    void* addr) {
  v8::Local<v8::Value> func =
      context->Global()->Get(context, v8_str(func_name)).ToLocalChecked();
  CHECK(func->IsFunction());
  Tagged<JSFunction> js_func =
      Cast<JSFunction>(*v8::Utils::OpenDirectHandle(*func));
  return IsAddressWithinFuncCode(js_func, isolate, addr);
}

// This C++ function is called as a constructor, to grab the frame pointer
// from the calling function.  When this function runs, the stack contains
// a C_Entry frame and a Construct frame above the calling function's frame.
static void construct_call(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  i::StackFrameIterator frame_iterator(isolate);
  CHECK(frame_iterator.frame()->is_exit() ||
        frame_iterator.frame()->is_builtin_exit() ||
        frame_iterator.frame()->is_api_callback_exit());
  frame_iterator.Advance();
  CHECK(frame_iterator.frame()->is_construct() ||
        frame_iterator.frame()->is_fast_construct());
  frame_iterator.Advance();
  if (frame_iterator.frame()->type() == i::StackFrame::STUB) {
    // Skip over bytecode handler frame.
    frame_iterator.Advance();
  }
  i::StackFrame* calling_frame = frame_iterator.frame();
  CHECK(calling_frame->is_javascript());

  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
#if defined(V8_HOST_ARCH_32_BIT)
  int32_t low_bits = static_cast<int32_t>(calling_frame->fp());
  info.This()
      ->Set(context, v8_str("low_bits"), v8_num(low_bits >> 1))
      .FromJust();
#elif defined(V8_HOST_ARCH_64_BIT)
  Address fp = calling_frame->fp();
  uint64_t kSmiValueMask =
      (static_cast<uintptr_t>(1) << (kSmiValueSize - 1)) - 1;
  int32_t low_bits = static_cast<int32_t>(fp & kSmiValueMask);
  fp >>= kSmiValueSize - 1;
  int32_t high_bits = static_cast<int32_t>(fp & kSmiValueMask);
  fp >>= kSmiValueSize - 1;
  CHECK_EQ(fp, 0);  // Ensure all the bits are successfully encoded.
  info.This()->Set(context, v8_str("low_bits"), v8_int(low_bits)).FromJust();
  info.This()->Set(context, v8_str("high_bits"), v8_int(high_bits)).FromJust();
#else
#error Host architecture is neither 32-bit nor 64-bit.
#endif
  info.GetReturnValue().Set(info.This());
}

// Use the API to create a JSFunction object that calls the above C++ function.
void CreateFramePointerGrabberConstructor(v8::Local<v8::Context> context,
                                          const char* constructor_name) {
    Local<v8::FunctionTemplate> constructor_template =
        v8::FunctionTemplate::New(context->GetIsolate(), construct_call);
    constructor_template->SetClassName(v8_str("FPGrabber"));
    Local<Function> fun =
        constructor_template->GetFunction(context).ToLocalChecked();
    context->Global()->Set(context, v8_str(constructor_name), fun).FromJust();
}


// Creates a global function named 'func_name' that calls the tracing
// function 'trace_func_name' with an actual EBP register value,
// encoded as one or two Smis.
static void CreateTraceCallerFunction(v8::Local<v8::Context> context,
                                      const char* func_name,
                                      const char* trace_func_name) {
  v8::base::EmbeddedVector<char, 256> trace_call_buf;
  v8::base::SNPrintF(trace_call_buf,
                     "function %s() {"
                     "  fp = new FPGrabber();"
                     "  %s(fp.low_bits, fp.high_bits);"
                     "}",
                     func_name, trace_func_name);

  // Create the FPGrabber function, which grabs the caller's frame pointer
  // when called as a constructor.
  CreateFramePointerGrabberConstructor(context, "FPGrabber");

  // Compile the script.
  CompileRun(trace_call_buf.begin());
}


// This test verifies that stack tracing works when called during
// execution of a native function called from JS code. In this case,
// TickSample::Trace uses Isolate::c_entry_fp as a starting point for stack
// walking.
TEST(CFromJSStackTrace) {
  // BUG(1303) Inlining of JSFuncDoTrace() in JSTrace below breaks this test.
  i::v8_flags.turbo_inlining = false;

  TickSample sample;
  i::TraceExtension::InitTraceEnv(&sample);

  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> context = CcTest::NewContext({TRACE_EXTENSION_ID});
  v8::Context::Scope context_scope(context);

  // Create global function JSFuncDoTrace which calls
  // extension function trace() with the current frame pointer value.
  CreateTraceCallerFunction(context, "JSFuncDoTrace", "trace");
  Local<Value> result = CompileRun(
      "function JSTrace() {"
      "         JSFuncDoTrace();"
      "};\n"
      "JSTrace();\n"
      "true;");
  CHECK(!result.IsEmpty());
  // When stack tracer is invoked, the stack should look as follows:
  // script [JS]
  //   JSTrace() [JS]
  //     JSFuncDoTrace() [JS] [captures EBP value and encodes it as Smi]
  //       trace(EBP) [native (extension)]
  //         DoTrace(EBP) [native]
  //           TickSample::Trace

  CHECK(sample.has_external_callback);
  CHECK_EQ(FUNCTION_ADDR(i::TraceExtension::Trace),
           reinterpret_cast<Address>(sample.external_callback_entry));

  // Stack tracing will start from the first JS function, i.e. "JSFuncDoTrace"
  unsigned base = 0;
  CHECK_GT(sample.frames_count, base + 1);

  CHECK(IsAddressWithinFuncCode(context, CcTest::i_isolate(), "JSFuncDoTrace",
                                sample.stack[base + 0]));
  CHECK(IsAddressWithinFuncCode(context, CcTest::i_isolate(), "JSTrace",
                                sample.stack[base + 1]));
}


// This test verifies that stack tracing works when called during
// execution of JS code. However, as calling TickSample::Trace requires
// entering native code, we can only emulate pure JS by erasing
// Isolate::c_entry_fp value. In this case, TickSample::Trace uses passed frame
// pointer value as a starting point for stack walking.
TEST(PureJSStackTrace) {
  // This test does not pass with inlining enabled since inlined functions
  // don't appear in the stack trace.
  i::v8_flags.turbo_inlining = false;

  TickSample sample;
  i::TraceExtension::InitTraceEnv(&sample);

  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> context = CcTest::NewContext({TRACE_EXTENSION_ID});
  v8::Context::Scope context_scope(context);

  // Create global function JSFuncDoTrace which calls
  // extension function js_trace() with the current frame pointer value.
  CreateTraceCallerFunction(context, "JSFuncDoTrace", "js_trace");
  Local<Value> result = CompileRun(
      "function JSTrace() {"
      "         JSFuncDoTrace();"
      "};\n"
      "function OuterJSTrace() {"
      "         JSTrace();"
      "};\n"
      "OuterJSTrace();\n"
      "true;");
  CHECK(!result.IsEmpty());
  // When stack tracer is invoked, the stack should look as follows:
  // script [JS]
  //   OuterJSTrace() [JS]
  //     JSTrace() [JS]
  //       JSFuncDoTrace() [JS]
  //         js_trace(EBP) [native (extension)]
  //           DoTraceHideCEntryFPAddress(EBP) [native]
  //             TickSample::Trace
  //

  CHECK(sample.has_external_callback);
  CHECK_EQ(FUNCTION_ADDR(i::TraceExtension::JSTrace),
           reinterpret_cast<Address>(sample.external_callback_entry));

  // Stack sampling will start from the caller of JSFuncDoTrace, i.e. "JSTrace"
  unsigned base = 0;
  CHECK_GT(sample.frames_count, base + 1);
  CHECK(IsAddressWithinFuncCode(context, CcTest::i_isolate(), "JSTrace",
                                sample.stack[base + 0]));
  CHECK(IsAddressWithinFuncCode(context, CcTest::i_isolate(), "OuterJSTrace",
                                sample.stack[base + 1]));
}

static void CFuncDoTrace(uint8_t dummy_param) {
  Address fp;
#if V8_HAS_BUILTIN_FRAME_ADDRESS
  fp = reinterpret_cast<Address>(__builtin_frame_address(0));
#elif V8_CC_MSVC
  // Approximate a frame pointer address. We compile without base pointers,
  // so we can't trust ebp/rbp.
  fp = reinterpret_cast<Address>(&dummy_param) - 2 * sizeof(void*);
#else
#error Unexpected platform.
#endif
  i::TraceExtension::DoTrace(fp);
}

static int CFunc(int depth) {
  if (depth <= 0) {
    CFuncDoTrace(0);
    return 0;
  } else {
    return CFunc(depth - 1) + 1;
  }
}


// This test verifies that stack tracing doesn't crash when called on
// pure native code. TickSample::Trace only unrolls JS code, so we can't
// get any meaningful info here.
TEST(PureCStackTrace) {
  TickSample sample;
  i::TraceExtension::InitTraceEnv(&sample);
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> context = CcTest::NewContext({TRACE_EXTENSION_ID});
  v8::Context::Scope context_scope(context);
  // Check that sampler doesn't crash
  CHECK_EQ(10, CFunc(10));
}


TEST(JsEntrySp) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::Context> context = CcTest::NewContext({TRACE_EXTENSION_ID});
  v8::Context::Scope context_scope(context);
  CHECK(!i::TraceExtension::GetJsEntrySp());
  CompileRun("a = 1; b = a + 1;");
  CHECK(!i::TraceExtension::GetJsEntrySp());
  CompileRun("js_entry_sp();");
  CHECK(!i::TraceExtension::GetJsEntrySp());
  CompileRun("js_entry_sp_level2();");
  CHECK(!i::TraceExtension::GetJsEntrySp());
}

}  // namespace internal
}  // namespace v8

"""

```