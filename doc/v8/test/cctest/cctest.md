Response:
Let's break down the thought process for analyzing this C++ code and answering the user's request.

**1. Understanding the Core Request:**

The user wants to understand the functionality of `v8/test/cctest/cctest.cc`. They also have some specific follow-up questions related to Torque files, JavaScript interaction, logic, and common errors.

**2. Initial Code Scan and Keyword Spotting:**

The first step is to quickly scan the code for important keywords and patterns. This gives a high-level overview:

* **Copyright and License:** Standard boilerplate, indicating V8 project.
* **Includes:** A significant number of `#include` directives. These hint at the file's dependencies and purpose. Keywords like `test`, `cctest`, `v8`, `libplatform`, `compiler`, `objects`, `flags`, `heap`, `extension` stand out. This strongly suggests this file is part of the V8 testing infrastructure.
* **`CcTest` Class:**  This class appears central. Its members like `callback_`, `initialize_`, `isolate_`, `allocator_` are key to understanding its role.
* **`main` function:** This is the entry point of the program, confirming it's an executable. The logic inside `main` involving argument parsing (`--list`), finding tests, and running them is crucial.
* **`Run` method:** This method within `CcTest` seems responsible for setting up and executing individual tests.
* **`InitializeVM`, `NewContext`:**  These methods suggest interaction with the V8 JavaScript engine itself.
* **Platform Abstraction:**  The code uses `v8::Platform` and `TestPlatform`, indicating a need to abstract platform-specific details.
* **Macros and Defines:**  `V8_ENABLE_TURBOFAN`, `V8_USE_PERFETTO`, `V8_OS_WIN`, `V8_CC_MSVC` suggest conditional compilation based on build settings.
* **Testing Infrastructure:** The presence of `g_cctests`, the logic for registering and running tests, and the `CcTest` constructor all point to a testing framework.

**3. Inferring Functionality:**

Based on the initial scan, it's highly likely that `cctest.cc` is the core of a V8 component test framework. It allows writing and running individual C++ tests for V8 functionality.

* **Test Registration:** The `CcTest` constructor registers a test function (`callback_`) with a name.
* **Test Execution:** The `main` function parses arguments, finds the requested test, and the `Run` method executes it.
* **V8 Initialization:** The `Run` method initializes the V8 engine (including the platform and ICU).
* **Context Creation:**  Methods like `InitializeVM` and `NewContext` manage V8 contexts for test execution.
* **Memory Management:** The `allocator_` member suggests managing memory for V8 objects within tests.
* **Extensions:**  The registration of `PrintExtension`, `ProfilerExtension`, and `TraceExtension` indicates the ability to extend the testing environment.

**4. Addressing Specific Questions:**

* **`.tq` extension:**  The code explicitly checks for the `.tq` extension, linking it to Torque. This is a direct code observation.
* **JavaScript Relation:** The includes for `v8-context.h`, `v8-function.h`, the methods for creating contexts, and the registration of extensions clearly show a relationship with JavaScript functionality. The example of creating a global function is a natural illustration.
* **Code Logic and Input/Output:**  The test registration and execution flow have clear logic. A simple example of running a named test is straightforward.
* **Common Programming Errors:**  The code includes checks for already existing tests and the need to dispose of isolates, hinting at potential errors related to resource management and naming conflicts. The `DCHECK_EQ` for isolate disposal reinforces this.

**5. Structuring the Answer:**

Organize the findings into logical sections:

* **Core Functionality:** Start with the most important aspect – it's a testing framework.
* **Detailed Features:** Elaborate on test registration, execution, V8 initialization, context management, etc.
* **Torque:**  Address the `.tq` question directly.
* **JavaScript Interaction:** Explain the connection and provide a concrete JavaScript example.
* **Code Logic Example:**  Illustrate with a simple test execution scenario.
* **Common Errors:**  Provide examples based on observations in the code.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Is this *only* for component tests?  Looking at the includes, it seems broader than just isolated components; it interacts with core V8 functionality. Refine the description accordingly.
* **JavaScript Example:**  Instead of a complex example, keep it simple and focused on the core idea of creating and using V8 functions within the test environment.
* **Error Examples:** Focus on errors that are directly suggested by the code (e.g., naming conflicts, resource leaks) rather than more general programming errors.

By following this thought process, combining code analysis with domain knowledge about V8, and structuring the information clearly, we can arrive at a comprehensive and accurate answer to the user's request.
`v8/test/cctest/cctest.cc` 是 V8 JavaScript 引擎项目中的一个核心文件，它定义了一个基于 C++ 的测试框架，用于对 V8 的各个组件进行单元测试和集成测试。它的主要功能是：

**1. 定义和管理 C++ 测试用例:**

* **`CcTest` 类:**  这是测试用例的基类。它封装了测试函数、测试名称、以及一些测试相关的配置（例如是否需要初始化 V8 引擎）。
* **测试注册机制:**  通过 `CcTest` 类的构造函数，可以将测试用例注册到一个全局的测试列表中 (`g_cctests`)。每个测试用例都有一个唯一的名称，由文件名和测试名组成。
* **`main` 函数:**  程序的入口点，负责解析命令行参数，查找并执行指定的测试用例。它还提供了列出所有可用测试用例的功能 (`--list`)。

**2. V8 引擎的生命周期管理:**

* **初始化和清理:** `CcTest::Run` 方法负责在测试用例执行前后初始化和清理 V8 引擎。这包括初始化平台、ICU 库、外部启动数据等。
* **Isolate 管理:**  `CcTest` 类可以创建一个 `v8::Isolate` 实例，这是 V8 引擎的独立实例，用于执行 JavaScript 代码。测试用例可以选择是否需要创建和管理自己的 Isolate。
* **Context 管理:** 提供创建和进入 V8 上下文 (`v8::Context`) 的方法，用于执行 JavaScript 代码。

**3. 提供测试辅助工具:**

* **全局函数注册:** `CcTest::AddGlobalFunction` 方法允许在测试上下文中注册全局 C++ 函数，这些函数可以被 JavaScript 代码调用，方便测试 V8 和 C++ 代码的交互。
* **字符串创建:**  `CcTest::MakeString` 和 `CcTest::MakeName` 方法用于方便地创建 V8 字符串对象。
* **随机数生成器:**  提供一个随机数生成器供测试使用。
* **访问堆和只读堆:**  `CcTest::heap()` 和 `CcTest::read_only_heap()` 可以访问 V8 的堆内存，方便进行堆相关的测试。

**4. 支持不同的测试配置:**

* **平台抽象:**  通过 `v8::Platform` 抽象了底层操作系统平台，使得测试可以跨平台运行。
* **扩展支持:**  允许注册自定义的 V8 扩展，例如 `PrintExtension`、`ProfilerExtension`、`TraceExtension`，用于在测试中提供额外的功能。

**如果 `v8/test/cctest/cctest.cc` 以 `.tq` 结尾:**

那么它将是一个 **V8 Torque 源代码**。Torque 是 V8 使用的一种领域特定语言 (DSL)，用于生成 V8 内部的 C++ 代码，特别是用于实现内置函数和运行时功能。在这种情况下，该文件将包含 Torque 代码，描述 V8 内部的操作。

**与 JavaScript 功能的关系 (以及 JavaScript 示例):**

`cctest.cc` 及其定义的测试框架与 JavaScript 功能有着直接的关系。它用于测试 V8 执行 JavaScript 代码的正确性、性能以及各种边缘情况。

**JavaScript 示例:**

假设在 `cctest.cc` 中定义了一个测试用例，需要测试 JavaScript 中 `Array.prototype.map` 方法的功能。测试用例可能会包含以下步骤：

1. **创建一个 V8 Isolate 和 Context。**
2. **执行一段 JavaScript 代码，这段代码调用 `Array.prototype.map`。**
3. **检查 `map` 方法的返回值是否符合预期。**

```cpp
// 在 cctest.cc 中定义的测试用例可能如下：
TEST(ArrayMap) {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);

    // 执行 JavaScript 代码
    v8::Local<v8::String> source =
        v8::String::NewFromUtf8Literal(isolate, "[1, 2, 3].map(x => x * 2)");
    v8::Local<v8::Script> script =
        v8::Script::Compile(context, source).ToLocalChecked();
    v8::Local<v8::Value> result = script->Run(context).ToLocalChecked();

    // 验证结果
    v8::Local<v8::Array> resultArray = v8::Local<v8::Array>::Cast(result);
    CHECK_EQ(3, resultArray->Length());
    CHECK_EQ(2, resultArray->Get(context, 0).ToLocalChecked()->Int32Value(context).FromJust());
    CHECK_EQ(4, resultArray->Get(context, 1).ToLocalChecked()->Int32Value(context).FromJust());
    CHECK_EQ(6, resultArray->Get(context, 2).ToLocalChecked()->Int32Value(context).FromJust());
  }
  isolate->Dispose();
}
```

**代码逻辑推理 (假设输入与输出):**

考虑 `CcTest::Run` 方法中的测试执行逻辑。

**假设输入:**

* 命令行参数: `./cctest ArrayMap` (假设存在一个名为 `ArrayMap` 的测试用例)
* `g_cctests` 包含一个名为 `ArrayMap` 的 `CcTest` 对象，其 `callback_` 成员指向上面 JavaScript 示例中的测试函数。

**推理过程:**

1. `main` 函数解析命令行参数，找到要运行的测试用例名称 `ArrayMap`。
2. 在 `g_cctests` 中查找名为 `ArrayMap` 的测试用例。
3. 调用该测试用例的 `Run` 方法。
4. `CcTest::Run` 方法会执行以下步骤：
    * 初始化 V8 平台等。
    * 如果测试用例配置需要初始化 Isolate，则创建一个新的 Isolate 并进入。
    * 调用测试用例的 `callback_` 函数 (也就是上面 JavaScript 示例中的代码)。
    * `callback_` 函数会创建 Context，执行 JavaScript 代码，并进行断言检查。
    * 如果测试通过，断言不会失败。
    * 清理 Isolate (如果创建了)。
    * 清理 V8 平台等。

**预期输出:**

如果测试用例中的断言都成立，程序将正常退出，不会有任何错误输出。如果断言失败，程序会输出错误信息并异常退出。

**涉及用户常见的编程错误 (举例说明):**

由于 `cctest.cc` 是一个测试框架，它本身不会直接涉及用户的编程错误。但是，**在编写使用该框架的测试用例时**，可能会遇到一些常见的编程错误，例如：

1. **忘记释放 V8 对象:**  V8 使用句柄 (handles) 来管理 JavaScript 对象。如果忘记使用 `v8::HandleScope` 或释放局部句柄，可能会导致内存泄漏。

   ```cpp
   // 错误示例
   TEST(MemoryLeak) {
     v8::Isolate::CreateParams create_params;
     create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
     v8::Isolate* isolate = v8::Isolate::New(create_params);
     {
       v8::Isolate::Scope isolate_scope(isolate);
       // 忘记创建 HandleScope
       v8::Local<v8::Context> context = v8::Context::New(isolate);
       // ... 创建了很多 V8 对象，但没有及时释放
     }
     isolate->Dispose();
   }
   ```

2. **在错误的上下文中操作 V8 对象:**  V8 对象只能在其所属的 Isolate 和 Context 中使用。尝试在错误的 Isolate 或 Context 中操作对象会导致崩溃或其他不可预测的行为。

   ```cpp
   // 错误示例
   v8::Local<v8::Context> global_context;

   TEST(WrongContext) {
     v8::Isolate::CreateParams create_params;
     create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
     v8::Isolate* isolate1 = v8::Isolate::New(create_params);
     {
       v8::Isolate::Scope isolate_scope(isolate1);
       v8::HandleScope handle_scope(isolate1);
       global_context = v8::Context::New(isolate1);
     }
     isolate1->Dispose();

     v8::Isolate* isolate2 = v8::Isolate::New(create_params);
     {
       v8::Isolate::Scope isolate_scope(isolate2);
       v8::HandleScope handle_scope(isolate2);
       v8::Context::Scope context_scope(v8::Context::New(isolate2));
       // 尝试在 isolate2 的上下文中访问 isolate1 的 context
       v8::Local<v8::String> str = v8::String::NewFromUtf8Literal(isolate2, "test");
       global_context->Global()->Set(v8::Context::GetCurrentContext(), str, str); // 错误！
     }
     isolate2->Dispose();
   }
   ```

3. **不正确的类型转换:**  在 V8 API 中进行类型转换时，如果类型不匹配，会导致程序崩溃。应该使用 `ToLocalChecked()` 或进行显式检查。

   ```cpp
   // 错误示例
   TEST(IncorrectCast) {
     v8::Isolate::CreateParams create_params;
     create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
     v8::Isolate* isolate = v8::Isolate::New(create_params);
     {
       v8::Isolate::Scope isolate_scope(isolate);
       v8::HandleScope handle_scope(isolate);
       v8::Local<v8::Context> context = v8::Context::New(isolate);
       v8::Context::Scope context_scope(context);

       v8::Local<v8::Value> number = v8::Number::New(isolate, 10);
       // 错误地将 Number 转换为 String 而不进行检查
       v8::Local<v8::String> str = v8::Local<v8::String>::Cast(number); // 可能崩溃
     }
     isolate->Dispose();
   }
   ```

理解 `v8/test/cctest/cctest.cc` 的功能对于理解 V8 的测试流程以及如何为 V8 贡献测试用例至关重要。它提供了一个结构化的方式来验证 V8 的各个方面，确保其稳定性和正确性。

### 提示词
```
这是目录为v8/test/cctest/cctest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/cctest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2008 the V8 project authors. All rights reserved.
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

#include "test/cctest/cctest.h"

#include "include/cppgc/platform.h"
#include "include/libplatform/libplatform.h"
#include "include/v8-array-buffer.h"
#include "include/v8-context.h"
#include "include/v8-function.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-locker.h"
#include "src/base/lazy-instance.h"
#include "src/base/logging.h"
#include "src/base/platform/condition-variable.h"
#include "src/base/platform/mutex.h"
#include "src/base/platform/semaphore.h"
#include "src/base/strings.h"
#include "src/codegen/compiler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/common/globals.h"
#include "src/init/v8.h"
#ifdef V8_ENABLE_TURBOFAN
#include "src/compiler/pipeline.h"
#endif  // V8_ENABLE_TURBOFAN
#include "src/flags/flags.h"
#include "src/objects/objects-inl.h"
#include "src/trap-handler/trap-handler.h"
#include "test/cctest/heap/heap-utils.h"
#include "test/cctest/print-extension.h"
#include "test/cctest/profiler-extension.h"
#include "test/cctest/trace-extension.h"

#ifdef V8_USE_PERFETTO
#include "src/tracing/trace-event.h"
#endif  // V8_USE_PERFETTO

#if V8_OS_WIN
#include <windows.h>
#if V8_CC_MSVC
#include <crtdbg.h>
#endif
#endif

enum InitializationState { kUnset, kUninitialized, kInitialized };
static InitializationState initialization_state_ = kUnset;

static v8::base::LazyInstance<CcTestMapType>::type g_cctests =
    LAZY_INSTANCE_INITIALIZER;

std::unordered_map<std::string, CcTest*>* tests_ =
    new std::unordered_map<std::string, CcTest*>();
bool CcTest::initialize_called_ = false;
v8::base::Atomic32 CcTest::isolate_used_ = 0;
v8::ArrayBuffer::Allocator* CcTest::allocator_ = nullptr;
v8::Isolate* CcTest::isolate_ = nullptr;
v8::Platform* CcTest::default_platform_ = nullptr;

CcTest::CcTest(TestFunction* callback, const char* file, const char* name,
               bool enabled, bool initialize,
               TestPlatformFactory* test_platform_factory)
    : callback_(callback),
      initialize_(initialize),
      test_platform_factory_(test_platform_factory) {
  // Find the base name of this test (const_cast required on Windows).
  char *basename = strrchr(const_cast<char *>(file), '/');
  if (!basename) {
    basename = strrchr(const_cast<char *>(file), '\\');
  }
  if (!basename) {
    basename = v8::internal::StrDup(file);
  } else {
    basename = v8::internal::StrDup(basename + 1);
  }
  // Drop the extension, if there is one.
  char *extension = strrchr(basename, '.');
  if (extension) *extension = 0;
  // Install this test in the list of tests

  if (enabled) {
    auto it =
        g_cctests.Pointer()->emplace(std::string(basename) + "/" + name, this);
    CHECK_WITH_MSG(it.second, "Test with same name already exists");
  }
  v8::internal::DeleteArray(basename);
}

void CcTest::Run(const char* snapshot_directory) {
  v8::V8::InitializeICUDefaultLocation(snapshot_directory);
  std::unique_ptr<v8::Platform> underlying_default_platform(
      v8::platform::NewDefaultPlatform());
  default_platform_ = underlying_default_platform.get();
  std::unique_ptr<v8::Platform> platform;
  if (test_platform_factory_) {
    platform = test_platform_factory_();
  } else {
    platform = std::move(underlying_default_platform);
  }
  i::V8::InitializePlatformForTesting(platform.get());
  cppgc::InitializeProcess(platform->GetPageAllocator());

  // Allow changing flags in cctests.
  // TODO(12887): Fix tests to avoid changing flag values after initialization.
  i::v8_flags.freeze_flags_after_init = false;

  v8::V8::Initialize();
  v8::V8::InitializeExternalStartupData(snapshot_directory);

#if V8_ENABLE_WEBASSEMBLY && V8_TRAP_HANDLER_SUPPORTED
  constexpr bool kUseDefaultTrapHandler = true;
  CHECK(v8::V8::EnableWebAssemblyTrapHandler(kUseDefaultTrapHandler));
#endif  // V8_ENABLE_WEBASSEMBLY && V8_TRAP_HANDLER_SUPPORTED

  CcTest::set_array_buffer_allocator(
      v8::ArrayBuffer::Allocator::NewDefaultAllocator());

  v8::RegisterExtension(std::make_unique<i::PrintExtension>());
  v8::RegisterExtension(std::make_unique<i::ProfilerExtension>());
  v8::RegisterExtension(std::make_unique<i::TraceExtension>());

  if (!initialize_) {
    CHECK_NE(initialization_state_, kInitialized);
    initialization_state_ = kUninitialized;
    CHECK_NULL(isolate_);
  } else {
    CHECK_NE(initialization_state_, kUninitialized);
    initialization_state_ = kInitialized;
    CHECK_NULL(isolate_);
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = allocator_;
    isolate_ = v8::Isolate::New(create_params);
    isolate_->Enter();
  }
#ifdef DEBUG
  const size_t active_isolates = i::Isolate::non_disposed_isolates();
#endif  // DEBUG
  callback_();
#ifdef DEBUG
  // This DCHECK ensures that all Isolates are properly disposed after finishing
  // the test. Stray Isolates lead to stray tasks in the platform which can
  // interact weirdly when swapping in new platforms (for testing) or during
  // shutdown.
  DCHECK_EQ(active_isolates, i::Isolate::non_disposed_isolates());
#endif  // DEBUG
  if (initialize_) {
    if (i_isolate()->was_locker_ever_used()) {
      v8::Locker locker(isolate_);
      EmptyMessageQueues(isolate_);
    } else {
      EmptyMessageQueues(isolate_);
    }
    isolate_->Exit();
    isolate_->Dispose();
    isolate_ = nullptr;
  } else {
    CHECK_NULL(isolate_);
  }

  v8::V8::Dispose();
  cppgc::ShutdownProcess();
  v8::V8::DisposePlatform();
}

i::Heap* CcTest::heap() { return i_isolate()->heap(); }
i::ReadOnlyHeap* CcTest::read_only_heap() {
  return i_isolate()->read_only_heap();
}

void CcTest::AddGlobalFunction(v8::Local<v8::Context> env, const char* name,
                               v8::FunctionCallback callback) {
  v8::Local<v8::FunctionTemplate> func_template =
      v8::FunctionTemplate::New(isolate_, callback);
  v8::Local<v8::Function> func =
      func_template->GetFunction(env).ToLocalChecked();
  func->SetName(v8_str(name));
  env->Global()->Set(env, v8_str(name), func).FromJust();
}

i::Handle<i::String> CcTest::MakeString(const char* str) {
  i::Isolate* isolate = CcTest::i_isolate();
  i::Factory* factory = isolate->factory();
  return factory->InternalizeUtf8String(str);
}

i::Handle<i::String> CcTest::MakeName(const char* str, int suffix) {
  v8::base::EmbeddedVector<char, 128> buffer;
  v8::base::SNPrintF(buffer, "%s%d", str, suffix);
  return CcTest::MakeString(buffer.begin());
}

v8::base::RandomNumberGenerator* CcTest::random_number_generator() {
  return InitIsolateOnce()->random_number_generator();
}

v8::Local<v8::Object> CcTest::global() {
  return isolate()->GetCurrentContext()->Global();
}

void CcTest::InitializeVM() {
  CHECK(!v8::base::Relaxed_Load(&isolate_used_));
  CHECK(!initialize_called_);
  initialize_called_ = true;
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::Context::New(CcTest::isolate())->Enter();
}

v8::Local<v8::Context> CcTest::NewContext(CcTestExtensionFlags extension_flags,
                                          v8::Isolate* isolate) {
  const char* extension_names[kMaxExtensions];
  int extension_count = 0;
  for (int i = 0; i < kMaxExtensions; ++i) {
    if (!extension_flags.contains(static_cast<CcTestExtensionId>(i))) continue;
    extension_names[extension_count] = kExtensionName[i];
    ++extension_count;
  }
  v8::ExtensionConfiguration config(extension_count, extension_names);
  v8::Local<v8::Context> context = v8::Context::New(isolate, &config);
  CHECK(!context.IsEmpty());
  return context;
}

LocalContext::~LocalContext() {
  v8::HandleScope scope(isolate_);
  v8::Local<v8::Context>::New(isolate_, context_)->Exit();
  context_.Reset();
}

void LocalContext::Initialize(v8::Isolate* isolate,
                              v8::ExtensionConfiguration* extensions,
                              v8::Local<v8::ObjectTemplate> global_template,
                              v8::Local<v8::Value> global_object) {
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context =
      v8::Context::New(isolate, extensions, global_template, global_object);
  context_.Reset(isolate, context);
  context->Enter();
  // We can't do this later perhaps because of a fatal error.
  isolate_ = isolate;
}

// This indirection is needed because HandleScopes cannot be heap-allocated, and
// we don't want any unnecessary #includes in cctest.h.
class V8_NODISCARD InitializedHandleScopeImpl {
 public:
  explicit InitializedHandleScopeImpl(i::Isolate* isolate)
      : handle_scope_(isolate) {}

 private:
  i::HandleScope handle_scope_;
};

InitializedHandleScope::InitializedHandleScope(i::Isolate* isolate)
    : main_isolate_(isolate ? isolate : CcTest::InitIsolateOnce()),
      initialized_handle_scope_impl_(
          new InitializedHandleScopeImpl(main_isolate_)) {}

InitializedHandleScope::~InitializedHandleScope() = default;

HandleAndZoneScope::HandleAndZoneScope(bool support_zone_compression)
    : main_zone_(
          new i::Zone(&allocator_, ZONE_NAME, support_zone_compression)) {}

HandleAndZoneScope::~HandleAndZoneScope() = default;

#ifdef V8_ENABLE_TURBOFAN
i::Handle<i::JSFunction> Optimize(i::Handle<i::JSFunction> function,
                                  i::Zone* zone, i::Isolate* isolate,
                                  uint32_t flags) {
  i::Handle<i::SharedFunctionInfo> shared(function->shared(), isolate);
  i::IsCompiledScope is_compiled_scope(shared->is_compiled_scope(isolate));
  CHECK(is_compiled_scope.is_compiled() ||
        i::Compiler::Compile(isolate, function, i::Compiler::CLEAR_EXCEPTION,
                             &is_compiled_scope));

  CHECK_NOT_NULL(zone);

  i::OptimizedCompilationInfo info(zone, isolate, shared, function,
                                   i::CodeKind::TURBOFAN_JS);

  if (flags & ~i::OptimizedCompilationInfo::kInlining) UNIMPLEMENTED();
  if (flags & i::OptimizedCompilationInfo::kInlining) {
    info.set_inlining();
  }

  CHECK(info.shared_info()->HasBytecodeArray());
  i::JSFunction::EnsureFeedbackVector(isolate, function, &is_compiled_scope);

  i::DirectHandle<i::Code> code =
      i::compiler::Pipeline::GenerateCodeForTesting(&info, isolate)
          .ToHandleChecked();
  function->UpdateCode(*code);
  return function;
}
#endif  // V8_ENABLE_TURBOFAN

static void PrintTestList() {
  int test_num = 0;
  for (const auto& entry : g_cctests.Get()) {
    printf("**>Test: %s\n", entry.first.c_str());
    test_num++;
  }
  printf("\nTotal number of tests: %d\n", test_num);
}

int main(int argc, char* argv[]) {
#if V8_OS_WIN
  UINT new_flags =
      SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX;
  UINT existing_flags = SetErrorMode(new_flags);
  SetErrorMode(existing_flags | new_flags);
#if V8_CC_MSVC
  _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG | _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
  _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG | _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
  _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG | _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
  _set_error_mode(_OUT_TO_STDERR);
#endif  // V8_CC_MSVC
#endif  // V8_OS_WIN

  std::string usage = "Usage: " + std::string(argv[0]) + " [--list]" +
                      " [[V8_FLAGS] CCTEST]\n\n" + "Options:\n" +
                      "  --list:   list all cctests\n" +
                      "  CCTEST:   cctest identfier returned by --list\n" +
                      "  V8_FLAGS: see V8 options below\n\n\n";

#ifdef V8_USE_PERFETTO
  // Set up the in-process backend that the tracing controller will connect to.
  perfetto::TracingInitArgs init_args;
  init_args.backends = perfetto::BackendType::kInProcessBackend;
  perfetto::Tracing::Initialize(init_args);
#endif  // V8_USE_PERFETTO

  using HelpOptions = v8::internal::FlagList::HelpOptions;
  v8::internal::FlagList::SetFlagsFromCommandLine(
      &argc, argv, true, HelpOptions(HelpOptions::kExit, usage.c_str()));

  const char* test_arg = nullptr;
  for (int i = 1; i < argc; ++i) {
    const char* arg = argv[i];
    if (strcmp(arg, "--list") == 0) {
      PrintTestList();
      return 0;
    }
    if (*arg == '-') {
      // Ignore flags that weren't removed by SetFlagsFromCommandLine
      continue;
    }
    if (test_arg != nullptr) {
      fprintf(stderr,
              "Running multiple tests in sequence is not allowed. Use "
              "tools/run-tests.py instead.\n");
      return 1;
    }
    test_arg = arg;
  }

  if (test_arg == nullptr) {
    printf("Ran 0 tests.\n");
    return 0;
  }

  auto it = g_cctests.Get().find(test_arg);
  if (it == g_cctests.Get().end()) {
    fprintf(stderr, "ERROR: Did not find test %s.\n", test_arg);
    return 1;
  }

  CcTest* test = it->second;
  test->Run(argv[0]);

  return 0;
}

std::vector<const RegisterThreadedTest*> RegisterThreadedTest::tests_;

bool IsValidUnwrapObject(v8::Object* object) {
  i::Address addr = i::ValueHelper::ValueAsAddress(object);
  auto instance_type = i::Internals::GetInstanceType(addr);
  return (v8::base::IsInRange(instance_type,
                              i::Internals::kFirstJSApiObjectType,
                              i::Internals::kLastJSApiObjectType) ||
          instance_type == i::Internals::kJSObjectType ||
          instance_type == i::Internals::kJSSpecialApiObjectType);
}

v8::PageAllocator* TestPlatform::GetPageAllocator() {
  return CcTest::default_platform()->GetPageAllocator();
}

void TestPlatform::OnCriticalMemoryPressure() {
  CcTest::default_platform()->OnCriticalMemoryPressure();
}

int TestPlatform::NumberOfWorkerThreads() {
  return CcTest::default_platform()->NumberOfWorkerThreads();
}

std::shared_ptr<v8::TaskRunner> TestPlatform::GetForegroundTaskRunner(
    v8::Isolate* isolate, v8::TaskPriority priority) {
  return CcTest::default_platform()->GetForegroundTaskRunner(isolate, priority);
}

void TestPlatform::PostTaskOnWorkerThreadImpl(
    v8::TaskPriority priority, std::unique_ptr<v8::Task> task,
    const v8::SourceLocation& location) {
  CcTest::default_platform()->CallOnWorkerThread(std::move(task));
}

void TestPlatform::PostDelayedTaskOnWorkerThreadImpl(
    v8::TaskPriority priority, std::unique_ptr<v8::Task> task,
    double delay_in_seconds, const v8::SourceLocation& location) {
  CcTest::default_platform()->CallDelayedOnWorkerThread(std::move(task),
                                                        delay_in_seconds);
}

std::unique_ptr<v8::JobHandle> TestPlatform::CreateJobImpl(
    v8::TaskPriority priority, std::unique_ptr<v8::JobTask> job_task,
    const v8::SourceLocation& location) {
  return CcTest::default_platform()->CreateJob(priority, std::move(job_task),
                                               location);
}

double TestPlatform::MonotonicallyIncreasingTime() {
  return CcTest::default_platform()->MonotonicallyIncreasingTime();
}

double TestPlatform::CurrentClockTimeMillis() {
  return CcTest::default_platform()->CurrentClockTimeMillis();
}

bool TestPlatform::IdleTasksEnabled(v8::Isolate* isolate) {
  return CcTest::default_platform()->IdleTasksEnabled(isolate);
}

v8::TracingController* TestPlatform::GetTracingController() {
  return CcTest::default_platform()->GetTracingController();
}

namespace {

class ShutdownTask final : public v8::Task {
 public:
  ShutdownTask(v8::base::Semaphore* destruction_barrier,
               v8::base::Mutex* destruction_mutex,
               v8::base::ConditionVariable* destruction_condition,
               bool* can_destruct)
      : destruction_barrier_(destruction_barrier),
        destruction_mutex_(destruction_mutex),
        destruction_condition_(destruction_condition),
        can_destruct_(can_destruct)

  {}

  void Run() final {
    destruction_barrier_->Signal();
    {
      v8::base::MutexGuard guard(destruction_mutex_);
      while (!*can_destruct_) {
        destruction_condition_->Wait(destruction_mutex_);
      }
    }
    destruction_barrier_->Signal();
  }

 private:
  v8::base::Semaphore* const destruction_barrier_;
  v8::base::Mutex* const destruction_mutex_;
  v8::base::ConditionVariable* const destruction_condition_;
  bool* const can_destruct_;
};

}  // namespace
```