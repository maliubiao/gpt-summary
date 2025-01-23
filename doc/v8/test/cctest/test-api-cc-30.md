Response:
My thinking process to analyze the given C++ code and fulfill the prompt's requirements goes like this:

1. **Understand the Goal:** The prompt asks for an analysis of a V8 test file (`test-api.cc`). The key is to identify the functionalities being tested and provide explanations, examples, and highlight potential errors. The prompt also specifies checking for `.tq` extension (Torque) and summarizing the overall purpose of this specific part of the test suite.

2. **Initial Scan for Keywords and Patterns:** I'll quickly scan the code for common test-related keywords and V8 API usage:
    * `TEST(...)`:  Indicates individual test cases.
    * `LocalContext`, `v8::Isolate`, `v8::HandleScope`, `v8::Context`:  Core V8 object management.
    * `v8_str(...)`, `v8_num(...)`: Likely helper functions for creating V8 string and number objects.
    * `CompileRun(...)`:  Executes JavaScript code within the test environment.
    * `CHECK(...)`, `CHECK_EQ(...)`, `CHECK_NE(...)`, `CheckDoubleEquals(...)`: Assertion macros.
    * `Module`, `ScriptCompiler`: Related to JavaScript module loading and compilation.
    * `PrimitiveArray`, `PersistentValueMap`:  V8 data structures.
    * `AtomicsWaitCallback`:  Focuses on asynchronous operations and callbacks.
    * `SharedArrayBuffer`: Related to concurrency and shared memory.
    * `BigInt`:  Testing the BigInt JavaScript type.
    * `GetJSEntryStubs`:  Checking internal V8 function entry points.
    * `MicrotaskContext`:  Verifying the context in which microtasks run.
    * `PreviewEntries`: Testing methods for peeking at the contents of iterators.
    * `WasmRunner`, `WASM_*`: Indicate tests related to WebAssembly.

3. **Group Tests by Functionality:** Based on the initial scan, I can start grouping the tests:

    * **Module Tests:**  `ModuleScriptIdentity`, `ModuleIsSourceTextModule`. These clearly deal with the behavior of JavaScript modules.
    * **Context/Global Object Tests:** `GlobalTemplateWithDoubleProperty`. This checks how properties are set on the global object.
    * **Data Structure Tests:** `PrimitiveArray`, `PersistentValueMap`. These test the specific functionalities of these V8 data structures.
    * **Atomics Tests:** `AtomicsWaitCallback`, `WasmI32AtomicWaitCallback`, `WasmI64AtomicWaitCallback`. These are related to the `Atomics` JavaScript API for synchronization.
    * **WebAssembly Tests:** `WasmCodeFlushingOnMemoryPressure`, `WasmI32AtomicWaitCallback`, `WasmI64AtomicWaitCallback`. (Note that the Atomics tests might overlap with WebAssembly tests if they test WebAssembly's implementation of Atomics).
    * **BigInt Tests:** `BigIntAPI`. Specifically tests the functionality of the BigInt JavaScript type and its C++ API.
    * **Internal V8 API Tests:** `GetJSEntryStubs`, `MicrotaskContextShouldBeNativeContext`. These tests delve into V8's internal workings.
    * **Iterator Preview Tests:** `PreviewSetKeysIteratorEntriesWithDeleted`, `PreviewSetValuesIteratorEntriesWithDeleted`, `PreviewMapEntriesIteratorEntries`, `PreviewMapValuesIteratorEntriesWithDeleted`. These focus on the `PreviewEntries` API for iterators of Set and Map.

4. **Analyze Each Test Case:** For each group of tests, I will:

    * **Describe the Functionality:** Explain what the test is trying to verify. For example, `ModuleScriptIdentity` checks that a module's script ID remains the same before and after instantiation.
    * **Check for JavaScript Relevance:** If the test involves JavaScript interaction, I'll provide a simple JavaScript example demonstrating the feature being tested. For the module tests, this involves `export` and `import`. For `Atomics.wait`, a basic example of using it. For `BigInt`, creating BigInt literals. For Set/Map iterators, creating and iterating over them.
    * **Identify Code Logic and Provide Examples:** If the test involves specific logic or conditions, I'll create hypothetical inputs and expected outputs. For example, in the `AtomicsWaitCallback` tests, the inputs are the parameters to `Atomics.wait`, and the outputs are the different outcomes based on the callback's actions.
    * **Point out Potential Programming Errors:** Based on the tested functionalities, I'll suggest common mistakes developers might make. For example, with modules, forgetting `export` or `import`. With `Atomics.wait`, incorrect usage of shared memory or timeouts. With BigInt, potential loss of precision when converting to standard numbers.
    * **Check for Torque (`.tq`):** I'll explicitly state that this file doesn't have the `.tq` extension and therefore isn't a Torque file.

5. **Address Specific Prompt Requirements:**

    * **Listing Functionality:**  This is covered by the analysis of each test case.
    * **Torque Check:** Explicitly done.
    * **JavaScript Examples:** Provided where applicable.
    * **Code Logic/Input-Output:** Included in the analysis of relevant tests.
    * **Common Programming Errors:**  Specifically addressed.

6. **Summarize the Functionality:** After analyzing all the tests, I'll write a concise summary of the overall purpose of this specific part of the `test-api.cc` file. The summary will highlight the main areas being tested: module loading, core data structures, concurrency primitives (Atomics), WebAssembly integration, BigInt support, internal V8 APIs, and iterator preview features.

7. **Review and Refine:** Finally, I'll review my analysis for clarity, accuracy, and completeness, ensuring that all aspects of the prompt are addressed. I'll make sure the JavaScript examples are correct and easy to understand, and that the explanations of the C++ code are clear. I'll also double-check that the identified common errors are relevant to the tested functionalities.

By following this structured approach, I can systematically analyze the C++ code, extract the relevant information, and generate a comprehensive response that satisfies all the requirements of the prompt.
好的，让我们来分析一下这段 `v8/test/cctest/test-api.cc` 的代码片段。

**功能列举:**

这段代码主要测试了 V8 JavaScript 引擎的以下 API 功能：

1. **模块 (Modules):**
   - **模块脚本标识 (Module Script Identity):**  测试模块在实例化前后是否拥有相同的 `UnboundModuleScript` 对象。这确保了模块的脚本信息在实例化过程中保持一致。
   - **模块脚本ID (Module Script Id):** 测试模块在实例化前后是否拥有相同的脚本 ID，并且该 ID 不是 `kNoScriptId`。
   - **模块类型判断 (Module Is SourceTextModule):**  测试通过 `ScriptCompiler::CompileModule` 编译的模块是否被正确识别为源文本模块 (`IsSourceTextModule`)，并且不是合成模块 (`IsSyntheticModule`)。

2. **全局对象模板 (Global Object Template):**
   - **设置双精度浮点数属性 (GlobalTemplateWithDoubleProperty):** 测试能否在全局对象模板上设置双精度浮点数属性，并在 JavaScript 代码中访问到。

3. **原始值数组 (Primitive Array):**
   - **创建和操作原始值数组 (PrimitiveArray):**  测试 `v8::PrimitiveArray` 的创建、获取长度、设置和获取不同类型的原始值（Symbol, String, Number, Boolean, Null）。

4. **持久化值映射 (PersistentValueMap):**
   - **创建和设置持久化值映射 (PersistentValueMap):** 测试 `v8::PersistentValueMap` 的创建和设置字符串键值对的功能。

5. **Atomics.wait 回调 (AtomicsWaitCallback):**
   - **设置和触发 Atomics.wait 回调 (AtomicsWaitCallback):**  测试 `v8::Isolate::SetAtomicsWaitCallback` 函数，模拟 `Atomics.wait` 的不同状态（中断、超时、不等、API停止等），并验证回调函数的行为。

6. **WebAssembly 集成 (Wasm - 如果启用):**
   - **内存压力下的 WebAssembly 代码刷新 (WasmCodeFlushingOnMemoryPressure):**  测试在内存压力下，Liftoff 编译的 WebAssembly 代码是否会被刷新。
   - **WebAssembly 的 Atomics.wait 回调 (WasmI32AtomicWaitCallback, WasmI64AtomicWaitCallback):** 测试 WebAssembly 中 `i32.atomic.wait` 和 `i64.atomic.wait` 指令与 V8 的 `AtomicsWaitCallback` 的集成。

7. **BigInt API:**
   - **BigInt 值的创建和获取 (BigIntAPI):** 测试 `v8::BigInt` 的创建（通过 JavaScript 字符串和 C++ API）以及获取其 `Uint64Value`、`Int64Value` 和底层 words 的功能。

8. **JSEntryStubs:**
   - **获取 JSEntryStubs (GetJSEntryStubs):** 测试能否获取到 V8 引擎中用于 JavaScript 函数调用的入口存根 (`JSEntryStubs`)，并验证其代码地址。

9. **微任务上下文 (Microtask Context):**
   - **微任务上下文应为原生上下文 (MicrotaskContextShouldBeNativeContext):** 测试异步操作（例如 `async/await` 和 `then`）产生的微任务是否在原生上下文 (Native Context) 中执行。

10. **迭代器预览 (Iterator Preview):**
    - **预览 Set 迭代器的键和值 (PreviewSetKeysIteratorEntriesWithDeleted, PreviewSetValuesIteratorEntriesWithDeleted):** 测试 `v8::Object::PreviewEntries` 方法用于预览 Set 迭代器（keys 和 values）的功能，包括在迭代器创建后删除 Set 中元素的情况。
    - **预览 Map 迭代器的键值对 (PreviewMapEntriesIteratorEntries):** 测试 `v8::Object::PreviewEntries` 方法用于预览 Map 的 entries 迭代器的功能。
    - **预览 Map 迭代器的值 (PreviewMapValuesIteratorEntriesWithDeleted):** 测试 `v8::Object::PreviewEntries` 方法用于预览 Map 的 values 迭代器的功能，包括在迭代器创建后删除 Map 中元素的情况。

**关于 `.tq` 扩展名:**

正如代码注释所说，如果 `v8/test/cctest/test-api.cc` 以 `.tq` 结尾，那么它会是一个 V8 Torque 源代码文件。然而，当前的 `.cc` 扩展名表明这是一个 C++ 文件，包含了使用 V8 C++ API 进行的测试。

**与 JavaScript 功能的关系及示例:**

以下是一些测试用例与 JavaScript 功能的对应关系和示例：

* **模块:**
  ```javascript
  // 对应 TEST(ModuleScriptIdentity), TEST(ModuleScriptId), TEST(ModuleIsSourceTextModule)
  // my_module.js
  export default 5;
  export const a = 10;

  // main.js
  import defaultValue, { a } from './my_module.js';
  console.log(defaultValue); // 输出 5
  console.log(a);          // 输出 10
  ```

* **全局对象模板:**
  ```javascript
  // 对应 TEST(GlobalTemplateWithDoubleProperty)
  console.log(double); // 如果全局对象模板设置了 "double" 属性，则会输出 3.14
  ```

* **Atomics.wait 回调:**
  ```javascript
  // 对应 TEST(AtomicsWaitCallback), TEST(WasmI32AtomicWaitCallback), TEST(WasmI64AtomicWaitCallback)
  const sab = new SharedArrayBuffer(4);
  const int32Array = new Int32Array(sab);
  let result = Atomics.wait(int32Array, 0, 0, 1000); // 等待 1 秒，如果 int32Array[0] 的值不是 0
  console.log(result); // 可能输出 "ok", "not-equal", "timed-out"
  ```

* **BigInt API:**
  ```javascript
  // 对应 TEST(BigIntAPI)
  const bigIntValue = 123456789012345678901234567890n;
  console.log(bigIntValue);
  ```

* **微任务上下文:**
  ```javascript
  // 对应 TEST(MicrotaskContextShouldBeNativeContext)
  async function testMicrotaskContext() {
    await 42;
    // 这里的代码会作为微任务执行
    console.log("Microtask executed");
  }
  testMicrotaskContext();
  ```

* **迭代器预览:**
  ```javascript
  // 对应 TEST(PreviewSetKeysIteratorEntriesWithDeleted), 等
  const set = new Set([1, 2, 3]);
  set.delete(1);
  const keysIterator = set.keys();
  // V8 内部机制可以预览迭代器中的剩余元素
  ```

**代码逻辑推理和假设输入输出:**

以 `TEST(AtomicsWaitCallback)` 为例：

**假设输入:**

1. 创建一个 `SharedArrayBuffer`，并创建一个 `Int32Array` 指向它。
2. 在 `Int32Array` 的某个索引位置设置初始值（例如 0）。
3. 调用 JavaScript 的 `Atomics.wait` 函数，指定要等待的索引、预期值和超时时间。
4. 通过 `v8::Isolate::SetAtomicsWaitCallback` 设置一个 C++ 回调函数。

**预期输出:**

根据 `AtomicsWaitCallbackForTesting` 函数中的 `action` 设置，会产生不同的结果：

* **`Interrupt`:**  `Atomics.wait` 会被中断，JavaScript 代码会抛出异常（`try_catch.HasTerminated()` 为真）。
* **`KeepWaiting` (但值不等):** `Atomics.wait` 会立即返回 "not-equal"。
* **`KeepWaiting` (超时):** `Atomics.wait` 会在超时后返回 "timed-out"。
* **`StopAndThrowInFirstCall` / `StopAndThrowInSecondCall` / `StopFromThreadAndThrow`:**  `Atomics.wait` 会被 API 停止，C++ 回调函数会抛出异常，该异常会被 JavaScript 的 `try...catch` 捕获。

**用户常见的编程错误举例:**

* **模块:**
    * 忘记使用 `export` 导出模块中的变量或函数。
    ```javascript
    // 错误示例
    const myVar = 10; // 没有 export

    // 另一个文件中尝试导入
    import { myVar } from './module.js'; // 报错：未找到 myVar
    ```
    * 导入时使用了错误的变量名。
    ```javascript
    // module.js
    export const counter = 0;

    // 错误示例
    import { count } from './module.js'; // 报错：找不到名为 count 的导出
    ```

* **Atomics.wait:**
    * 在非共享的 `ArrayBuffer` 上使用 `Atomics.wait` 会抛出 `TypeError`。
    * `Atomics.wait` 的超时时间使用不当，可能导致程序意外阻塞。
    * 忘记在其他线程或 worker 中使用 `Atomics.wake` 来唤醒等待的线程。

* **BigInt API:**
    * 将 `BigInt` 与普通数字进行运算时可能需要显式转换，否则会抛出 `TypeError`。
    ```javascript
    const bigIntVal = 10n;
    const numVal = 5;
    // const result = bigIntVal + numVal; // 报错：不能混合 BigInt 和 Number 进行运算
    const result = bigIntVal + BigInt(numVal); // 正确
    ```
    * 将非常大的 `BigInt` 转换为 `Number` 时可能丢失精度。

**功能归纳 (针对第 31 部分，共 36 部分):**

这段代码（第 31 部分）主要集中测试了 V8 引擎中 **模块系统、核心数据结构（PrimitiveArray, PersistentValueMap）、并发特性 (Atomics.wait)及其与 WebAssembly 的集成、BigInt 数据类型的支持、V8 引擎内部的入口点以及微任务的执行上下文**。 此外，还引入了 **迭代器预览** 的测试，这可能是一个相对较新的或正在开发中的功能。

考虑到这是 36 个部分中的第 31 部分，可以推测这个测试文件 (`test-api.cc`) 是一个相当全面的 API 功能测试集。  这一部分可能重点关注了 **JavaScript 的模块化、并发编程能力以及对大数据（BigInt）的支持**，同时也开始涉及一些更底层的 V8 引擎机制。 随着测试的进行，后续部分可能会涵盖其他 V8 API，例如对象、函数、类、错误处理、国际化等等。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第31部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
om");
  Local<String> source_text = v8_str("export default 5; export const a = 10;");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  Local<v8::UnboundModuleScript> sfi_before_instantiation =
      module->GetUnboundModuleScript();
  module->InstantiateModule(context.local(), UnexpectedModuleResolveCallback)
      .ToChecked();
  Local<v8::UnboundModuleScript> sfi_after_instantiation =
      module->GetUnboundModuleScript();

  // Check object identity.
  {
    i::DirectHandle<i::Object> s1 =
        v8::Utils::OpenDirectHandle(*sfi_before_instantiation);
    i::DirectHandle<i::Object> s2 =
        v8::Utils::OpenDirectHandle(*sfi_after_instantiation);
    CHECK_EQ(*s1, *s2);
  }
}

TEST(ModuleScriptId) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<String> url = v8_str("www.google.com");
  Local<String> source_text = v8_str("export default 5; export const a = 10;");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  int id_before_instantiation = module->ScriptId();
  module->InstantiateModule(context.local(), UnexpectedModuleResolveCallback)
      .ToChecked();
  int id_after_instantiation = module->ScriptId();

  CHECK_EQ(id_before_instantiation, id_after_instantiation);
  CHECK_NE(id_before_instantiation, v8::UnboundScript::kNoScriptId);
}

TEST(ModuleIsSourceTextModule) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<String> url = v8_str("www.google.com");
  Local<String> source_text = v8_str("export default 5; export const a = 10;");
  v8::ScriptOrigin origin(url, 0, 0, false, -1, Local<v8::Value>(), false,
                          false, true);
  v8::ScriptCompiler::Source source(source_text, origin);
  Local<Module> module =
      v8::ScriptCompiler::CompileModule(isolate, &source).ToLocalChecked();
  CHECK(module->IsSourceTextModule());
  CHECK(!module->IsSyntheticModule());
}

TEST(GlobalTemplateWithDoubleProperty) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
  global->Set(isolate, "double", v8_num(3.14));

  v8::Local<v8::Context> context = v8::Context::New(isolate, nullptr, global);

  v8::Context::Scope context_scope(context);

  Local<Value> result = CompileRun("double");
  CHECK(result->IsNumber());
  CheckDoubleEquals(3.14, result->NumberValue(context).ToChecked());
}

TEST(PrimitiveArray) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext env;

  int length = 5;
  Local<v8::PrimitiveArray> array(v8::PrimitiveArray::New(isolate, 5));
  CHECK_EQ(length, array->Length());

  for (int i = 0; i < length; i++) {
    Local<v8::Primitive> item = array->Get(isolate, i);
    CHECK(item->IsUndefined());
  }

  Local<v8::Symbol> symbol(v8::Symbol::New(isolate));
  array->Set(isolate, 0, symbol);
  CHECK(array->Get(isolate, 0)->IsSymbol());

  Local<v8::String> string = v8::String::NewFromUtf8Literal(
      isolate, "test", v8::NewStringType::kInternalized);
  array->Set(isolate, 1, string);
  CHECK(array->Get(isolate, 0)->IsSymbol());
  CHECK(array->Get(isolate, 1)->IsString());

  Local<v8::Number> num = v8::Number::New(env->GetIsolate(), 3.1415926);
  array->Set(isolate, 2, num);
  CHECK(array->Get(isolate, 0)->IsSymbol());
  CHECK(array->Get(isolate, 1)->IsString());
  CHECK(array->Get(isolate, 2)->IsNumber());

  v8::Local<v8::Boolean> f = v8::False(isolate);
  array->Set(isolate, 3, f);
  CHECK(array->Get(isolate, 0)->IsSymbol());
  CHECK(array->Get(isolate, 1)->IsString());
  CHECK(array->Get(isolate, 2)->IsNumber());
  CHECK(array->Get(isolate, 3)->IsBoolean());

  v8::Local<v8::Primitive> n = v8::Null(isolate);
  array->Set(isolate, 4, n);
  CHECK(array->Get(isolate, 0)->IsSymbol());
  CHECK(array->Get(isolate, 1)->IsString());
  CHECK(array->Get(isolate, 2)->IsNumber());
  CHECK(array->Get(isolate, 3)->IsBoolean());
  CHECK(array->Get(isolate, 4)->IsNull());
}

TEST(PersistentValueMap) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext env;

  v8::PersistentValueMap<
      std::string, v8::Value,
      v8::DefaultPersistentValueMapTraits<std::string, v8::Value>>
      map(isolate);
  v8::Local<v8::Value> value = v8::String::NewFromUtf8Literal(
      isolate, "value", v8::NewStringType::kInternalized);
  map.Set("key", value);
}

enum class AtomicsWaitCallbackAction {
  Interrupt,
  StopAndThrowInFirstCall,
  StopAndThrowInSecondCall,
  StopFromThreadAndThrow,
  KeepWaiting
};

class StopAtomicsWaitThread;

struct AtomicsWaitCallbackInfo {
  v8::Isolate* isolate;
  v8::Isolate::AtomicsWaitWakeHandle* wake_handle;
  std::unique_ptr<StopAtomicsWaitThread> stop_thread;
  AtomicsWaitCallbackAction action;

  Local<v8::SharedArrayBuffer> expected_sab;
  v8::Isolate::AtomicsWaitEvent expected_event;
  double expected_timeout;
  int64_t expected_value;
  size_t expected_offset;

  size_t ncalls = 0;
};

class StopAtomicsWaitThread : public v8::base::Thread {
 public:
  explicit StopAtomicsWaitThread(AtomicsWaitCallbackInfo* info)
      : Thread(Options("StopAtomicsWaitThread")), info_(info) {}

  void Run() override {
    CHECK_NOT_NULL(info_->wake_handle);
    info_->wake_handle->Wake();
  }

 private:
  AtomicsWaitCallbackInfo* info_;
};

void AtomicsWaitCallbackForTesting(
    v8::Isolate::AtomicsWaitEvent event, Local<v8::SharedArrayBuffer> sab,
    size_t offset_in_bytes, int64_t value, double timeout_in_ms,
    v8::Isolate::AtomicsWaitWakeHandle* wake_handle, void* data) {
  AtomicsWaitCallbackInfo* info = static_cast<AtomicsWaitCallbackInfo*>(data);
  info->ncalls++;
  info->wake_handle = wake_handle;
  CHECK(sab->StrictEquals(info->expected_sab));
  CHECK_EQ(timeout_in_ms, info->expected_timeout);
  CHECK_EQ(value, info->expected_value);
  CHECK_EQ(offset_in_bytes, info->expected_offset);
  CHECK_EQ(v8::StateTag::ATOMICS_WAIT,
           reinterpret_cast<i::Isolate*>(info->isolate)->current_vm_state());

  auto ThrowSomething = [&]() {
    info->isolate->ThrowException(v8::Integer::New(info->isolate, 42));
  };

  if (event == v8::Isolate::AtomicsWaitEvent::kStartWait) {
    CHECK_NOT_NULL(wake_handle);
    switch (info->action) {
      case AtomicsWaitCallbackAction::Interrupt:
        info->isolate->TerminateExecution();
        break;
      case AtomicsWaitCallbackAction::StopAndThrowInFirstCall:
        ThrowSomething();
        [[fallthrough]];
      case AtomicsWaitCallbackAction::StopAndThrowInSecondCall:
        wake_handle->Wake();
        break;
      case AtomicsWaitCallbackAction::StopFromThreadAndThrow:
        info->stop_thread = std::make_unique<StopAtomicsWaitThread>(info);
        CHECK(info->stop_thread->Start());
        break;
      case AtomicsWaitCallbackAction::KeepWaiting:
        break;
    }
  } else {
    CHECK_EQ(event, info->expected_event);
    CHECK_NULL(wake_handle);

    if (info->stop_thread) {
      info->stop_thread->Join();
      info->stop_thread.reset();
    }

    if (info->action == AtomicsWaitCallbackAction::StopAndThrowInSecondCall ||
        info->action == AtomicsWaitCallbackAction::StopFromThreadAndThrow) {
      ThrowSomething();
    }
  }
}

// Must be called from within HandleScope
void AtomicsWaitCallbackCommon(v8::Isolate* isolate, Local<Value> sab,
                               size_t initial_offset,
                               size_t offset_multiplier) {
  CHECK(sab->IsSharedArrayBuffer());

  AtomicsWaitCallbackInfo info;
  info.isolate = isolate;
  info.expected_sab = sab.As<v8::SharedArrayBuffer>();
  isolate->SetAtomicsWaitCallback(AtomicsWaitCallbackForTesting, &info);

  {
    v8::TryCatch try_catch(isolate);
    info.expected_offset = initial_offset;
    info.expected_timeout = std::numeric_limits<double>::infinity();
    info.expected_value = 0;
    info.expected_event = v8::Isolate::AtomicsWaitEvent::kTerminatedExecution;
    info.action = AtomicsWaitCallbackAction::Interrupt;
    info.ncalls = 0;
    CompileRun("wait(0, 0);");
    CHECK_EQ(info.ncalls, 2);
    CHECK(try_catch.HasTerminated());
  }

  {
    v8::TryCatch try_catch(isolate);
    info.expected_offset = initial_offset + offset_multiplier;
    info.expected_timeout = std::numeric_limits<double>::infinity();
    info.expected_value = 1;
    info.expected_event = v8::Isolate::AtomicsWaitEvent::kNotEqual;
    info.action = AtomicsWaitCallbackAction::KeepWaiting;
    info.ncalls = 0;
    CompileRun("wait(1, 1);");  // real value is 0 != 1
    CHECK_EQ(info.ncalls, 2);
    CHECK(!try_catch.HasCaught());
  }

  {
    v8::TryCatch try_catch(isolate);
    info.expected_offset = initial_offset + offset_multiplier;
    info.expected_timeout = 0.125;
    info.expected_value = 0;
    info.expected_event = v8::Isolate::AtomicsWaitEvent::kTimedOut;
    info.action = AtomicsWaitCallbackAction::KeepWaiting;
    info.ncalls = 0;
    CompileRun("wait(1, 0, 0.125);");  // timeout
    CHECK_EQ(info.ncalls, 2);
    CHECK(!try_catch.HasCaught());
  }

  {
    v8::TryCatch try_catch(isolate);
    info.expected_offset = initial_offset + offset_multiplier;
    info.expected_timeout = std::numeric_limits<double>::infinity();
    info.expected_value = 0;
    info.expected_event = v8::Isolate::AtomicsWaitEvent::kAPIStopped;
    info.action = AtomicsWaitCallbackAction::StopAndThrowInFirstCall;
    info.ncalls = 0;
    CompileRun("wait(1, 0);");
    CHECK_EQ(info.ncalls, 1);  // Only one extra call
    CHECK(try_catch.HasCaught());
    CHECK(try_catch.Exception()->IsInt32());
    CHECK_EQ(try_catch.Exception().As<v8::Int32>()->Value(), 42);
  }

  {
    v8::TryCatch try_catch(isolate);
    info.expected_offset = initial_offset + offset_multiplier;
    info.expected_timeout = std::numeric_limits<double>::infinity();
    info.expected_value = 0;
    info.expected_event = v8::Isolate::AtomicsWaitEvent::kAPIStopped;
    info.action = AtomicsWaitCallbackAction::StopAndThrowInSecondCall;
    info.ncalls = 0;
    CompileRun("wait(1, 0);");
    CHECK_EQ(info.ncalls, 2);
    CHECK(try_catch.HasCaught());
    CHECK(try_catch.Exception()->IsInt32());
    CHECK_EQ(try_catch.Exception().As<v8::Int32>()->Value(), 42);
  }

  {
    // Same test as before, but with a different `expected_value`.
    v8::TryCatch try_catch(isolate);
    info.expected_offset = initial_offset + offset_multiplier;
    info.expected_timeout = std::numeric_limits<double>::infinity();
    info.expected_value = 200;
    info.expected_event = v8::Isolate::AtomicsWaitEvent::kAPIStopped;
    info.action = AtomicsWaitCallbackAction::StopAndThrowInSecondCall;
    info.ncalls = 0;
    CompileRun(
        "setArrayElemAs(1, 200);"
        "wait(1, 200);");
    CHECK_EQ(info.ncalls, 2);
    CHECK(try_catch.HasCaught());
    CHECK(try_catch.Exception()->IsInt32());
    CHECK_EQ(try_catch.Exception().As<v8::Int32>()->Value(), 42);
  }

  {
    // Wake the `Atomics.wait()` call from a thread.
    v8::TryCatch try_catch(isolate);
    info.expected_offset = initial_offset;
    info.expected_timeout = std::numeric_limits<double>::infinity();
    info.expected_value = 0;
    info.expected_event = v8::Isolate::AtomicsWaitEvent::kAPIStopped;
    info.action = AtomicsWaitCallbackAction::StopFromThreadAndThrow;
    info.ncalls = 0;
    CompileRun(
        "setArrayElemAs(1, 0);"
        "wait(0, 0);");
    CHECK_EQ(info.ncalls, 2);
    CHECK(try_catch.HasCaught());
    CHECK(try_catch.Exception()->IsInt32());
    CHECK_EQ(try_catch.Exception().As<v8::Int32>()->Value(), 42);
  }
}

TEST(AtomicsWaitCallback) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  const char* init = R"(
      let sab = new SharedArrayBuffer(16);
      let int32arr = new Int32Array(sab, 4);
      let setArrayElemAs = function(id, val) {
        int32arr[id] = val;
      };
      let wait = function(id, val, timeout) {
        if(arguments.length == 2) return Atomics.wait(int32arr, id, val);
        return Atomics.wait(int32arr, id, val, timeout);
      };
      sab;)";
  AtomicsWaitCallbackCommon(isolate, CompileRun(init), 4, 4);
}

#if V8_ENABLE_WEBASSEMBLY
namespace v8::internal::wasm {

TEST(WasmCodeFlushingOnMemoryPressure) {
  i::v8_flags.flush_liftoff_code = true;
  WasmRunner<int32_t> r(TestExecutionTier::kLiftoff);
  r.Build({WASM_I32_ADD(WASM_I32V_1(11), WASM_I32V_1(44))});
  CHECK_EQ(55, r.Call());

  // We should have some Liftoff code compiled.
  CHECK_NE(GetWasmEngine()->GetLiftoffCodeSizeForTesting(), 0);

  v8::Isolate* isolate = CcTest::isolate();
  isolate->MemoryPressureNotification(v8::MemoryPressureLevel::kCritical);
  // When there is memory pressure, flush all Liftoff code.
  CHECK_EQ(GetWasmEngine()->GetLiftoffCodeSizeForTesting(), 0);
}

TEST(WasmI32AtomicWaitCallback) {
  WasmRunner<int32_t, int32_t, int32_t, double> r(TestExecutionTier::kTurbofan);
  r.builder().AddMemory(kWasmPageSize, SharedFlag::kShared);
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_WAIT(kExprI32AtomicWait, WASM_LOCAL_GET(0),
                             WASM_LOCAL_GET(1),
                             WASM_I64_SCONVERT_F64(WASM_LOCAL_GET(2)), 2, 4)});
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  Handle<JSFunction> func = r.builder().WrapCode(0);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("func"), v8::Utils::ToLocal(func))
            .FromJust());
  Handle<JSArrayBuffer> memory(
      r.builder().trusted_instance_data()->memory_object(0)->array_buffer(),
      i_isolate);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("sab"), v8::Utils::ToLocal(memory))
            .FromJust());

  const char* init = R"(
      let int32arr = new Int32Array(sab, 4);
      let setArrayElemAs = function(id, val) {
        int32arr[id] = val;
      };
      let wait = function(id, val, timeout) {
        if(arguments.length === 2)
          return func(id << 2, val, -1);
        return func(id << 2, val, timeout*1000000);
      };
      sab;)";
  AtomicsWaitCallbackCommon(isolate, CompileRun(init), 4, 4);
}

TEST(WasmI64AtomicWaitCallback) {
  WasmRunner<int32_t, int32_t, double, double> r(TestExecutionTier::kTurbofan);
  r.builder().AddMemory(kWasmPageSize, SharedFlag::kShared);
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_WAIT(kExprI64AtomicWait, WASM_LOCAL_GET(0),
                             WASM_I64_SCONVERT_F64(WASM_LOCAL_GET(1)),
                             WASM_I64_SCONVERT_F64(WASM_LOCAL_GET(2)), 3, 8)});
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  Handle<JSFunction> func = r.builder().WrapCode(0);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("func"), v8::Utils::ToLocal(func))
            .FromJust());
  Handle<JSArrayBuffer> memory(
      r.builder().trusted_instance_data()->memory_object(0)->array_buffer(),
      i_isolate);
  CHECK(env->Global()
            ->Set(env.local(), v8_str("sab"), v8::Utils::ToLocal(memory))
            .FromJust());

  const char* init = R"(
      let int64arr = new BigInt64Array(sab, 8);
      let setArrayElemAs = function(id, val) {
        int64arr[id] = BigInt(val);
      };
      let wait = function(id, val, timeout) {
        if(arguments.length === 2)
          return func(id << 3, val, -1);
        return func(id << 3, val, timeout*1000000);
      };
      sab;)";
  AtomicsWaitCallbackCommon(isolate, CompileRun(init), 8, 8);
}

}  // namespace v8::internal::wasm
#endif  // V8_ENABLE_WEBASSEMBLY

TEST(BigIntAPI) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  bool lossless;
  uint64_t words1[10];
  uint64_t words2[10];

  {
    Local<Value> bi = CompileRun("12n");
    CHECK(bi->IsBigInt());

    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(), 12);
    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(&lossless), 12);
    CHECK_EQ(lossless, true);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(), 12);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(&lossless), 12);
    CHECK_EQ(lossless, true);
  }

  {
    Local<Value> bi = CompileRun("-12n");
    CHECK(bi->IsBigInt());

    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(), static_cast<uint64_t>(-12));
    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(&lossless),
             static_cast<uint64_t>(-12));
    CHECK_EQ(lossless, false);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(), -12);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(&lossless), -12);
    CHECK_EQ(lossless, true);
  }

  {
    Local<Value> bi = CompileRun("123456789012345678901234567890n");
    CHECK(bi->IsBigInt());

    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(), 14083847773837265618ULL);
    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(&lossless),
             14083847773837265618ULL);
    CHECK_EQ(lossless, false);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(), -4362896299872285998LL);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(&lossless),
             -4362896299872285998LL);
    CHECK_EQ(lossless, false);
  }

  {
    Local<Value> bi = CompileRun("-123456789012345678901234567890n");
    CHECK(bi->IsBigInt());

    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(), 4362896299872285998LL);
    CHECK_EQ(bi.As<v8::BigInt>()->Uint64Value(&lossless),
             4362896299872285998LL);
    CHECK_EQ(lossless, false);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(), 4362896299872285998LL);
    CHECK_EQ(bi.As<v8::BigInt>()->Int64Value(&lossless), 4362896299872285998LL);
    CHECK_EQ(lossless, false);
  }

  {
    Local<v8::BigInt> bi =
        v8::BigInt::NewFromWords(env.local(), 0, 0, words1).ToLocalChecked();
    CHECK_EQ(bi->Uint64Value(), 0);
    CHECK_EQ(bi->WordCount(), 0);
  }

  {
    TryCatch try_catch(isolate);
    v8::MaybeLocal<v8::BigInt> bi = v8::BigInt::NewFromWords(
        env.local(), 0, std::numeric_limits<int>::max(), words1);
    CHECK(bi.IsEmpty());
    CHECK(try_catch.HasCaught());
  }

  {
    TryCatch try_catch(isolate);
    v8::MaybeLocal<v8::BigInt> bi =
        v8::BigInt::NewFromWords(env.local(), 0, -1, words1);
    CHECK(bi.IsEmpty());
    CHECK(try_catch.HasCaught());
  }

  {
    TryCatch try_catch(isolate);
    v8::MaybeLocal<v8::BigInt> bi =
        v8::BigInt::NewFromWords(env.local(), 0, 1 << 30, words1);
    CHECK(bi.IsEmpty());
    CHECK(try_catch.HasCaught());
  }

  for (int sign_bit = 0; sign_bit <= 1; sign_bit++) {
    words1[0] = 0xffffffff00000000ULL;
    words1[1] = 0x00000000ffffffffULL;
    v8::Local<v8::BigInt> bi =
        v8::BigInt::NewFromWords(env.local(), sign_bit, 2, words1)
            .ToLocalChecked();
    CHECK_EQ(bi->Uint64Value(&lossless),
             sign_bit ? static_cast<uint64_t>(-static_cast<int64_t>(words1[0]))
                      : words1[0]);
    CHECK_EQ(lossless, false);
    CHECK_EQ(bi->Int64Value(&lossless), sign_bit
                                            ? -static_cast<int64_t>(words1[0])
                                            : static_cast<int64_t>(words1[0]));
    CHECK_EQ(lossless, false);
    CHECK_EQ(bi->WordCount(), 2);
    int real_sign_bit;
    int word_count = arraysize(words2);
    bi->ToWordsArray(&real_sign_bit, &word_count, words2);
    CHECK_EQ(real_sign_bit, sign_bit);
    CHECK_EQ(word_count, 2);
  }
}

TEST(GetJSEntryStubs) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);

  v8::JSEntryStubs entry_stubs = isolate->GetJSEntryStubs();

  v8::JSEntryStub entry_stub = entry_stubs.js_entry_stub;
  CHECK_EQ(
      i_isolate->builtins()->code(i::Builtin::kJSEntry)->instruction_start(),
      reinterpret_cast<i::Address>(entry_stub.code.start));

  v8::JSEntryStub construct_stub = entry_stubs.js_construct_entry_stub;
  CHECK_EQ(i_isolate->builtins()
               ->code(i::Builtin::kJSConstructEntry)
               ->instruction_start(),
           reinterpret_cast<i::Address>(construct_stub.code.start));

  v8::JSEntryStub microtask_stub = entry_stubs.js_run_microtasks_entry_stub;
  CHECK_EQ(i_isolate->builtins()
               ->code(i::Builtin::kJSRunMicrotasksEntry)
               ->instruction_start(),
           reinterpret_cast<i::Address>(microtask_stub.code.start));
}

TEST(MicrotaskContextShouldBeNativeContext) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  auto callback = [](const v8::FunctionCallbackInfo<v8::Value>& info) {
    v8::Isolate* isolate = info.GetIsolate();
    v8::HandleScope scope(isolate);
    i::DirectHandle<i::Context> context =
        v8::Utils::OpenDirectHandle(*isolate->GetEnteredOrMicrotaskContext());

    CHECK(IsNativeContext(*context));
    info.GetReturnValue().SetUndefined();
  };

  Local<v8::FunctionTemplate> desc = v8::FunctionTemplate::New(isolate);
  desc->InstanceTemplate()->SetCallAsFunctionHandler(callback);
  Local<v8::Object> obj = desc->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();

  CHECK(env->Global()->Set(env.local(), v8_str("callback"), obj).FromJust());
  CompileRun(
      "with({}){(async ()=>{"
      "  await 42;"
      "})().then(callback);}");

  isolate->PerformMicrotaskCheckpoint();
}

TEST(PreviewSetKeysIteratorEntriesWithDeleted) {
  LocalContext env;
  v8::HandleScope handle_scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();

  {
    // Create set, delete entry, create iterator, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); set.delete(1); set.keys()")
            ->ToObject(context)
            .ToLocalChecked();
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(2, entries->Length());
    CHECK_EQ(2, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
    CHECK_EQ(3, entries->Get(context, 1)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create set, create iterator, delete entry, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); set.keys()")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1);");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(2, entries->Length());
    CHECK_EQ(2, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
    CHECK_EQ(3, entries->Get(context, 1)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create set, create iterator, delete entry, iterate, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); var it = set.keys(); it")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1); it.next();");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(1, entries->Length());
    CHECK_EQ(3, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create set, create iterator, delete entry, iterate until empty, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); var it = set.keys(); it")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1); it.next(); it.next();");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(0, entries->Length());
  }
  {
    // Create set, create iterator, delete entry, iterate, trigger rehash,
    // preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); var it = set.keys(); it")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1); it.next();");
    CompileRun("for (var i = 4; i < 20; i++) set.add(i);");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(17, entries->Length());
    for (uint32_t i = 0; i < 17; i++) {
      CHECK_EQ(i + 3, entries->Get(context, i)
                          .ToLocalChecked()
                          ->Int32Value(context)
                          .FromJust());
    }
  }
}

TEST(PreviewSetValuesIteratorEntriesWithDeleted) {
  LocalContext env;
  v8::HandleScope handle_scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();

  {
    // Create set, delete entry, create iterator, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); set.delete(1); set.values()")
            ->ToObject(context)
            .ToLocalChecked();
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(2, entries->Length());
    CHECK_EQ(2, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
    CHECK_EQ(3, entries->Get(context, 1)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create set, create iterator, delete entry, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); set.values()")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1);");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(2, entries->Length());
    CHECK_EQ(2, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
    CHECK_EQ(3, entries->Get(context, 1)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create set, create iterator, delete entry, iterate, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); var it = set.values(); it")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1); it.next();");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(1, entries->Length());
    CHECK_EQ(3, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create set, create iterator, delete entry, iterate until empty, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); var it = set.values(); it")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1); it.next(); it.next();");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(0, entries->Length());
  }
  {
    // Create set, create iterator, delete entry, iterate, trigger rehash,
    // preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); var it = set.values(); it")
            ->ToObject(context)
            .ToLocalChecked();
    CompileRun("set.delete(1); it.next();");
    CompileRun("for (var i = 4; i < 20; i++) set.add(i);");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(17, entries->Length());
    for (uint32_t i = 0; i < 17; i++) {
      CHECK_EQ(i + 3, entries->Get(context, i)
                          .ToLocalChecked()
                          ->Int32Value(context)
                          .FromJust());
    }
  }
}

TEST(PreviewMapEntriesIteratorEntries) {
  LocalContext env;
  v8::HandleScope handle_scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();
  {
    // Create set, delete entry, create entries iterator, preview.
    v8::Local<v8::Object> iterator =
        CompileRun("var set = new Set([1,2,3]); set.delete(2); set.entries()")
            ->ToObject(context)
            .ToLocalChecked();
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(is_key);
    CHECK_EQ(4, entries->Length());
    uint32_t first = entries->Get(context, 0)
                         .ToLocalChecked()
                         ->Int32Value(context)
                         .FromJust();
    uint32_t second = entries->Get(context, 2)
                          .ToLocalChecked()
                          ->Int32Value(context)
                          .FromJust();
    CHECK_EQ(1, first);
    CHECK_EQ(3, second);
    CHECK_EQ(first, entries->Get(context, 1)
                        .ToLocalChecked()
                        ->Int32Value(context)
                        .FromJust());
    CHECK_EQ(second, entries->Get(context, 3)
                         .ToLocalChecked()
                         ->Int32Value(context)
                         .FromJust());
  }
}

TEST(PreviewMapValuesIteratorEntriesWithDeleted) {
  LocalContext env;
  v8::HandleScope handle_scope(env->GetIsolate());
  v8::Local<v8::Context> context = env.local();

  {
    // Create map, delete entry, create iterator, preview.
    v8::Local<v8::Object> iterator = CompileRun(
                                         "var map = new Map();"
                                         "var key = {}; map.set(key, 1);"
                                         "map.set({}, 2); map.set({}, 3);"
                                         "map.delete(key);"
                                         "map.values()")
                                         ->ToObject(context)
                                         .ToLocalChecked();
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(2, entries->Length());
    CHECK_EQ(2, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
    CHECK_EQ(3, entries->Get(context, 1)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create map, create iterator, delete entry, preview.
    v8::Local<v8::Object> iterator = CompileRun(
                                         "var map = new Map();"
                                         "var key = {}; map.set(key, 1);"
                                         "map.set({}, 2); map.set({}, 3);"
                                         "map.values()")
                                         ->ToObject(context)
                                         .ToLocalChecked();
    CompileRun("map.delete(key);");
    bool is_key;
    v8::Local<v8::Array> entries =
        iterator->PreviewEntries(&is_key).ToLocalChecked();
    CHECK(!is_key);
    CHECK_EQ(2, entries->Length());
    CHECK_EQ(2, entries->Get(context, 0)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
    CHECK_EQ(3, entries->Get(context, 1)
                    .ToLocalChecked()
                    ->Int32Value(context)
                    .FromJust());
  }
  {
    // Create map, create iterator, delete entry, iterate, preview.
    v8::Local<v8::Object> iterator = CompileRun(
                                         "var map = new Map();"
```