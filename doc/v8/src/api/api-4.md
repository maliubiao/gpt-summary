Response: The user wants a summary of the C++ source code file `v8/src/api/api.cc`.
This is part 5 of an 8-part series, suggesting a focus on the functionalities covered in this specific chunk.
The request also asks for an explanation of the file's relation to JavaScript, with examples.

Looking at the code, it seems to define the public C++ API for V8, the JavaScript engine. This section appears to focus on:

1. **Initialization and Configuration:**  Functions related to initializing V8, including handling WebAssembly traps, setting error callbacks, entropy sources, and return address resolution.
2. **Memory Statistics:** Structures and a function to retrieve heap and shared memory statistics.
3. **Context Creation:** Functions for creating new JavaScript contexts, including those based on snapshots and remote contexts.
4. **Context Manipulation:** Functions to set and get security tokens, deep-freeze contexts, access the global object, manage microtask queues, control code generation, and set promise hooks.
5. **Object Template and Function Template:** Functions for creating and manipulating object and function templates, which are blueprints for creating JavaScript objects and functions.
6. **External Objects and Strings:** Functions for creating and managing external objects and strings, which allow embedding native data within JavaScript objects.
7. **String Creation:** Functions for creating different types of JavaScript strings (UTF-8, one-byte, two-byte, external).
8. **Object Creation:** Functions for creating plain JavaScript objects and wrapper objects for primitive types (Number, BigInt, Boolean, String, Symbol).
9. **Date Object:** Functions for creating and manipulating Date objects.
10. **RegExp Object:** Functions for creating and manipulating Regular Expression objects.

To illustrate the connection with JavaScript, I can use JavaScript code snippets that utilize the functionalities exposed by these C++ API functions.
这是 `v8/src/api/api.cc` 文件的第五部分，主要负责 V8 JavaScript 引擎的**上下文 (Context)** 和 **模板 (Template)** 相关的 API 功能。它涵盖了创建、配置和操作 JavaScript 上下文，以及定义 JavaScript 对象的蓝图（模板）的关键接口。

**主要功能归纳:**

1. **V8 初始化和配置的收尾工作:**
   - 检查 Embedder 和 V8 之间 `V8_ENABLE_CHECKS` 的编译配置是否一致，确保构建的正确性。
   - 调用内部的 `i::V8::Initialize()` 进行 V8 的核心初始化。

2. **WebAssembly 陷阱处理:**
   - 提供了跨平台处理 WebAssembly 陷阱的机制 (`TryHandleWebAssemblyTrapPosix`, `TryHandleWebAssemblyTrapWindows`, `EnableWebAssemblyTrapHandler`)，允许在 WebAssembly 代码执行出错时进行捕获和处理。

3. **错误处理回调:**
   - 允许设置致命内存错误的回调函数 (`SetFatalMemoryErrorCallback`)，在内存不足时通知宿主环境。
   - (在 Windows 上) 提供了设置未处理异常回调的接口 (`SetUnhandledExceptionCallback`)。

4. **随机数生成和调用栈信息:**
   - 允许设置自定义的熵源 (`SetEntropySource`)，影响 V8 的随机数生成。
   - 提供了设置返回地址位置解析器 (`SetReturnAddressLocationResolver`) 的能力，用于改进调用栈信息的准确性。

5. **V8 实例的释放:**
   - 提供 `Dispose()` 方法来清理 V8 引擎占用的资源。

6. **内存统计信息结构体:**
   - 定义了用于获取堆内存统计信息 (`HeapStatistics`, `HeapSpaceStatistics`, `HeapObjectStatistics`, `HeapCodeStatistics`) 和共享内存统计信息 (`SharedMemoryStatistics`) 的结构体。

7. **ICU (国际化组件) 的初始化:**
   - 提供了初始化 ICU 库的函数 (`InitializeICU`, `InitializeICUDefaultLocation`)，用于支持 JavaScript 的国际化功能。

8. **外部启动数据初始化:**
   - 允许设置外部启动数据 (`InitializeExternalStartupData`, `InitializeExternalStartupDataFromFile`)，用于加载快照 (Snapshot) 数据，加速 V8 的启动过程。

9. **获取 V8 版本:**
   - 提供 `GetVersion()` 方法来获取当前 V8 引擎的版本号。

10. **沙箱 (Sandbox) 相关功能 (如果启用):**
    - 提供了获取沙箱地址空间、大小和配置安全性的接口 (`GetSandboxAddressSpace`, `GetSandboxSizeInBytes`, `GetSandboxReservationSizeInBytes`, `IsSandboxConfiguredSecurely`)，用于增强 V8 的安全性。

11. **创建和管理 JavaScript 上下文 (Context):**
    - 提供了 `NewContext()` 函数，用于创建一个新的 JavaScript 执行上下文。可以指定全局对象模板、全局对象实例、扩展配置、快照索引等参数。
    - 提供了从快照创建上下文的 `FromSnapshot()` 函数。
    - 提供了创建远程上下文的 `NewRemoteContext()` 函数，用于在不同的隔离环境之间创建上下文。
    - 允许设置和获取上下文的安全令牌 (`SetSecurityToken`, `UseDefaultSecurityToken`, `GetSecurityToken`)，用于隔离不同上下文的代码。
    - 提供了深度冻结上下文对象的能力 (`DeepFreeze`)，使其及其包含的对象不可修改。
    - 提供了获取关联的 Isolate 实例 (`GetIsolate`) 和微任务队列 (`GetMicrotaskQueue`) 的方法，以及设置微任务队列的方法 (`SetMicrotaskQueue`).
    - 允许获取上下文的全局对象 (`Global`) 和解除全局对象的关联 (`DetachGlobal`).
    - 提供了访问额外的绑定对象 (`GetExtrasBindingObject`)、控制字符串生成代码的能力 (`AllowCodeGenerationFromStrings`, `IsCodeGenerationFromStringsAllowed`, `SetErrorMessageForCodeGenerationFromStrings`) 和 WASM 代码生成错误消息 (`SetErrorMessageForWasmCodeGeneration`) 的接口。
    - 允许设置脚本执行中止回调 (`SetAbortScriptExecution`)。
    - 提供了设置 Promise 钩子函数 (`SetPromiseHooks`) 的能力，用于监控 Promise 的生命周期。
    - 提供了检查是否包含模板字面量对象 (`HasTemplateLiteralObject`) 的方法。
    - 提供了与指标记录器交互的功能 (`metrics::Recorder::GetContext`, `metrics::Recorder::GetContextId`, `metrics::LongTaskStats::Get`).
    - 提供了从快照中获取一次性数据的功能 (`GetDataFromSnapshotOnce`).

12. **创建和管理对象模板 (ObjectTemplate):**
    - 提供了 `ObjectTemplate::NewInstance()` 函数，基于模板创建新的 JavaScript 对象实例。
    - 提供了静态的 `CheckCast()` 方法用于类型检查。

13. **创建和管理字典模板 (DictionaryTemplate):**
    - 提供了静态的 `CheckCast()` 方法用于类型检查。

14. **创建和管理函数模板 (FunctionTemplate):**
    - 提供了 `FunctionTemplate::GetFunction()` 函数，基于函数模板创建一个 JavaScript 函数。
    - 提供了 `FunctionTemplate::NewRemoteInstance()` 函数，创建远程对象实例。
    - 提供了检查值是否为模板实例的 `HasInstance()` 方法。
    - 提供了检查值是否为 API 对象的叶子模板的 `IsLeafTemplateForApiObject()` 方法。
    - 提供了静态的 `CheckCast()` 方法用于类型检查。

15. **创建和管理签名 (Signature):**
    - 提供了静态的 `CheckCast()` 方法用于类型检查。

16. **创建外部对象 (External):**
    - 提供了 `External::New()` 函数，创建一个包含 C++ 指针的 JavaScript 外部对象。
    - 提供了 `Value()` 方法来获取外部对象包含的 C++ 指针。

17. **创建 JavaScript 字符串 (String):**
    - 提供了多种创建字符串的方法，包括从 UTF-8 字符串字面量 (`NewFromUtf8Literal`)、UTF-8 编码 (`NewFromUtf8`)、单字节编码 (`NewFromOneByte`)、双字节编码 (`NewFromTwoByte`) 的 C++ 字符串创建。
    - 提供了连接字符串的方法 (`Concat`).
    - 提供了创建外部字符串的接口 (`NewExternalTwoByte`, `NewExternalOneByte`)，允许 JavaScript 字符串直接引用 C++ 层的字符数据，避免数据拷贝。
    - 提供了将现有 JavaScript 字符串转换为外部字符串的接口 (`MakeExternal`, `CanMakeExternal`).
    - 提供了比较字符串是否相等的方法 (`StringEquals`).

18. **创建 JavaScript 对象 (Object):**
    - 提供了 `Object::New()` 函数，创建普通的 JavaScript 对象。
    - 提供了 `Object::New()` 函数，可以指定原型对象以及初始的属性名和属性值。
    - 提供了 `GetIsolate()` 方法来获取关联的 Isolate 实例。

19. **创建基本类型包装对象 (NumberObject, BigIntObject, BooleanObject, StringObject, SymbolObject):**
    - 提供了创建 Number、BigInt、Boolean、String 和 Symbol 对象的包装器对象的方法 (`NumberObject::New`, `BigIntObject::New`, `BooleanObject::New`, `StringObject::New`, `SymbolObject::New`).
    - 提供了获取包装器对象原始值的方法 (`ValueOf`).

20. **创建 Date 对象 (Date):**
    - 提供了 `Date::New()` 函数，创建一个 JavaScript Date 对象。
    - 提供了 `Date::Parse()` 函数，解析字符串并创建 Date 对象。
    - 提供了 `ValueOf()` 方法来获取 Date 对象的时间戳。
    - 提供了将 Date 对象转换为 ISO 格式字符串 (`ToISOString`) 和 UTC 格式字符串 (`ToUTCString`) 的方法。

21. **创建 RegExp 对象 (RegExp):**
    - 提供了 `RegExp::New()` 函数，创建一个 JavaScript 正则表达式对象。
    - 提供了可以设置回溯限制的 `RegExp::NewWithBacktrackLimit()` 函数。
    - 提供了获取正则表达式源码 (`GetSource`) 和标志 (`GetFlags`) 的方法。
    - 提供了执行正则表达式匹配的 `Exec()` 方法。

**与 JavaScript 的关系及示例:**

这个文件定义了 V8 引擎暴露给宿主环境（例如浏览器、Node.js）的 C++ API。宿主环境可以通过这些 API 来控制 V8 引擎的运行，创建和操作 JavaScript 对象。

**JavaScript 示例:**

```javascript
// 假设在 Node.js 环境中

// 获取 V8 版本
const v8 = require('v8');
console.log(v8.getVersion());

// 创建一个新的 JavaScript 上下文 (Context)
const vm = require('vm');
const context = vm.createContext({ globalVar: 'hello' });

// 在上下文中执行 JavaScript 代码
vm.runInContext('console.log(globalVar);', context);

// 创建一个对象模板
const template = v8.ObjectTemplate.newInstance();
template.set('property1', v8.String::NewFromUtf8Literal('value1'));

// 基于模板创建一个对象
const localObject = template.NewInstance(context);
vm.runInContext('console.log(localObject.property1);', context);

// 创建一个外部对象，将 C++ 数据传递给 JavaScript
const externalData = { value: 42 };
const external = new v8.External(externalData);
context.external = external;
vm.runInContext('console.log(external.Value());', context);

// 创建一个字符串
const str = v8.String::NewFromUtf8Literal('JavaScript String');
console.log(str.length());

// 创建一个 Date 对象
const date = new Date();
console.log(date.toISOString());

// 创建一个 RegExp 对象
const regex = new RegExp('pattern', 'g');
console.log(regex.source);
```

**解释:**

- `require('v8')` 在 Node.js 中引入了 V8 模块，允许访问 V8 引擎的 API，这些 API 的底层实现就在 `v8/src/api/api.cc` 中定义。
- `vm.createContext()` 实际上调用了 `v8::Context::New()` 这样的 C++ API 来创建一个新的 V8 上下文。
- `v8.ObjectTemplate` 对应了 `v8::ObjectTemplate` C++ 类，`newInstance()` 对应 `NewInstance()` 方法。
- `new v8.External()` 对应了 `v8::External::New()` C++ 函数。
- `v8.String::NewFromUtf8Literal()`  等方法直接映射到 C++ 的字符串创建函数。
- JavaScript 的 `Date` 和 `RegExp` 对象在 V8 引擎内部也是通过 `v8::Date::New()` 和 `v8::RegExp::New()` 等 C++ API 创建的。

总而言之，这个文件是 V8 引擎提供给外部环境进行交互的核心接口，使得宿主环境能够创建、配置和操作 JavaScript 运行环境和对象。 JavaScript 代码最终调用的各种内置对象和功能，很多都是通过这个文件定义的 C++ API 实现的。

Prompt: 
```
这是目录为v8/src/api/api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共8部分，请归纳一下它的功能

"""
cks = true;
#else
  const bool kV8EnableChecks = false;
#endif
  if (kEmbedderEnableChecks != kV8EnableChecks) {
    FATAL(
        "Embedder-vs-V8 build configuration mismatch. On embedder side "
        "V8_ENABLE_CHECKS is %s while on V8 side it's %s.",
        kEmbedderEnableChecks ? "ENABLED" : "DISABLED",
        kV8EnableChecks ? "ENABLED" : "DISABLED");
  }

  i::V8::Initialize();
  return true;
}

#if V8_OS_LINUX || V8_OS_DARWIN
bool TryHandleWebAssemblyTrapPosix(int sig_code, siginfo_t* info,
                                   void* context) {
#if V8_ENABLE_WEBASSEMBLY && V8_TRAP_HANDLER_SUPPORTED
  return i::trap_handler::TryHandleSignal(sig_code, info, context);
#else
  return false;
#endif
}
#endif

#if V8_OS_WIN
bool TryHandleWebAssemblyTrapWindows(EXCEPTION_POINTERS* exception) {
#if V8_ENABLE_WEBASSEMBLY && V8_TRAP_HANDLER_SUPPORTED
  return i::trap_handler::TryHandleWasmTrap(exception);
#else
  return false;
#endif
}
#endif

bool V8::EnableWebAssemblyTrapHandler(bool use_v8_signal_handler) {
#if V8_ENABLE_WEBASSEMBLY
  return v8::internal::trap_handler::EnableTrapHandler(use_v8_signal_handler);
#else
  return false;
#endif
}

#if defined(V8_OS_WIN)
void V8::SetUnhandledExceptionCallback(
    UnhandledExceptionCallback unhandled_exception_callback) {
#if defined(V8_OS_WIN64)
  v8::internal::win64_unwindinfo::SetUnhandledExceptionCallback(
      unhandled_exception_callback);
#else
  // Not implemented, port needed.
#endif  // V8_OS_WIN64
}
#endif  // V8_OS_WIN

void v8::V8::SetFatalMemoryErrorCallback(
    v8::OOMErrorCallback oom_error_callback) {
  g_oom_error_callback = oom_error_callback;
}

void v8::V8::SetEntropySource(EntropySource entropy_source) {
  base::RandomNumberGenerator::SetEntropySource(entropy_source);
}

void v8::V8::SetReturnAddressLocationResolver(
    ReturnAddressLocationResolver return_address_resolver) {
  i::StackFrame::SetReturnAddressLocationResolver(return_address_resolver);
}

bool v8::V8::Dispose() {
  i::V8::Dispose();
  return true;
}

SharedMemoryStatistics::SharedMemoryStatistics()
    : read_only_space_size_(0),
      read_only_space_used_size_(0),
      read_only_space_physical_size_(0) {}

HeapStatistics::HeapStatistics()
    : total_heap_size_(0),
      total_heap_size_executable_(0),
      total_physical_size_(0),
      total_available_size_(0),
      used_heap_size_(0),
      heap_size_limit_(0),
      malloced_memory_(0),
      external_memory_(0),
      peak_malloced_memory_(0),
      does_zap_garbage_(false),
      number_of_native_contexts_(0),
      number_of_detached_contexts_(0) {}

HeapSpaceStatistics::HeapSpaceStatistics()
    : space_name_(nullptr),
      space_size_(0),
      space_used_size_(0),
      space_available_size_(0),
      physical_space_size_(0) {}

HeapObjectStatistics::HeapObjectStatistics()
    : object_type_(nullptr),
      object_sub_type_(nullptr),
      object_count_(0),
      object_size_(0) {}

HeapCodeStatistics::HeapCodeStatistics()
    : code_and_metadata_size_(0),
      bytecode_and_metadata_size_(0),
      external_script_source_size_(0),
      cpu_profiler_metadata_size_(0) {}

bool v8::V8::InitializeICU(const char* icu_data_file) {
  return i::InitializeICU(icu_data_file);
}

bool v8::V8::InitializeICUDefaultLocation(const char* exec_path,
                                          const char* icu_data_file) {
  return i::InitializeICUDefaultLocation(exec_path, icu_data_file);
}

void v8::V8::InitializeExternalStartupData(const char* directory_path) {
  i::InitializeExternalStartupData(directory_path);
}

// static
void v8::V8::InitializeExternalStartupDataFromFile(const char* snapshot_blob) {
  i::InitializeExternalStartupDataFromFile(snapshot_blob);
}

const char* v8::V8::GetVersion() { return i::Version::GetVersion(); }

#ifdef V8_ENABLE_SANDBOX
VirtualAddressSpace* v8::V8::GetSandboxAddressSpace() {
  Utils::ApiCheck(i::GetProcessWideSandbox()->is_initialized(),
                  "v8::V8::GetSandboxAddressSpace",
                  "The sandbox must be initialized first");
  return i::GetProcessWideSandbox()->address_space();
}

size_t v8::V8::GetSandboxSizeInBytes() {
  Utils::ApiCheck(i::GetProcessWideSandbox()->is_initialized(),
                  "v8::V8::GetSandboxSizeInBytes",
                  "The sandbox must be initialized first.");
  return i::GetProcessWideSandbox()->size();
}

size_t v8::V8::GetSandboxReservationSizeInBytes() {
  Utils::ApiCheck(i::GetProcessWideSandbox()->is_initialized(),
                  "v8::V8::GetSandboxReservationSizeInBytes",
                  "The sandbox must be initialized first");
  return i::GetProcessWideSandbox()->reservation_size();
}

bool v8::V8::IsSandboxConfiguredSecurely() {
  Utils::ApiCheck(i::GetProcessWideSandbox()->is_initialized(),
                  "v8::V8::IsSandoxConfiguredSecurely",
                  "The sandbox must be initialized first");
  // The sandbox is configured insecurely if either
  // * It is only partially reserved since in that case unrelated memory
  //   mappings may end up inside the sandbox address space where they could be
  //   corrupted by an attacker, or
  // * The first four GB of the address space were not reserved since in that
  //   case, Smi<->HeapObject confusions (treating a 32-bit Smi as a pointer)
  //   can also cause memory accesses to unrelated mappings.
  auto sandbox = i::GetProcessWideSandbox();
  return !sandbox->is_partially_reserved() &&
         sandbox->smi_address_range_is_inaccessible();
}
#endif  // V8_ENABLE_SANDBOX

void V8::GetSharedMemoryStatistics(SharedMemoryStatistics* statistics) {
  i::ReadOnlyHeap::PopulateReadOnlySpaceStatistics(statistics);
}

template <typename ObjectType>
struct InvokeBootstrapper;

template <>
struct InvokeBootstrapper<i::NativeContext> {
  i::DirectHandle<i::NativeContext> Invoke(
      i::Isolate* i_isolate,
      i::MaybeHandle<i::JSGlobalProxy> maybe_global_proxy,
      v8::Local<v8::ObjectTemplate> global_proxy_template,
      v8::ExtensionConfiguration* extensions, size_t context_snapshot_index,
      i::DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
      v8::MicrotaskQueue* microtask_queue) {
    return i_isolate->bootstrapper()->CreateEnvironment(
        maybe_global_proxy, global_proxy_template, extensions,
        context_snapshot_index, embedder_fields_deserializer, microtask_queue);
  }
};

template <>
struct InvokeBootstrapper<i::JSGlobalProxy> {
  i::DirectHandle<i::JSGlobalProxy> Invoke(
      i::Isolate* i_isolate,
      i::MaybeHandle<i::JSGlobalProxy> maybe_global_proxy,
      v8::Local<v8::ObjectTemplate> global_proxy_template,
      v8::ExtensionConfiguration* extensions, size_t context_snapshot_index,
      i::DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
      v8::MicrotaskQueue* microtask_queue) {
    USE(extensions);
    USE(context_snapshot_index);
    return i_isolate->bootstrapper()->NewRemoteContext(maybe_global_proxy,
                                                       global_proxy_template);
  }
};

template <typename ObjectType>
static i::DirectHandle<ObjectType> CreateEnvironment(
    i::Isolate* i_isolate, v8::ExtensionConfiguration* extensions,
    v8::MaybeLocal<ObjectTemplate> maybe_global_template,
    v8::MaybeLocal<Value> maybe_global_proxy, size_t context_snapshot_index,
    i::DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
    v8::MicrotaskQueue* microtask_queue) {
  i::DirectHandle<ObjectType> result;

  {
    ENTER_V8_FOR_NEW_CONTEXT(i_isolate);
    v8::Local<ObjectTemplate> proxy_template;
    i::Handle<i::FunctionTemplateInfo> proxy_constructor;
    i::Handle<i::FunctionTemplateInfo> global_constructor;
    i::DirectHandle<i::UnionOf<i::Undefined, i::InterceptorInfo>>
        named_interceptor(i_isolate->factory()->undefined_value());
    i::DirectHandle<i::UnionOf<i::Undefined, i::InterceptorInfo>>
        indexed_interceptor(i_isolate->factory()->undefined_value());

    if (!maybe_global_template.IsEmpty()) {
      v8::Local<v8::ObjectTemplate> global_template =
          maybe_global_template.ToLocalChecked();
      // Make sure that the global_template has a constructor.
      global_constructor = EnsureConstructor(i_isolate, *global_template);

      // Create a fresh template for the global proxy object.
      proxy_template =
          ObjectTemplate::New(reinterpret_cast<v8::Isolate*>(i_isolate));
      proxy_constructor = EnsureConstructor(i_isolate, *proxy_template);

      // Set the global template to be the prototype template of
      // global proxy template.
      i::FunctionTemplateInfo::SetPrototypeTemplate(
          i_isolate, proxy_constructor, Utils::OpenHandle(*global_template));

      proxy_template->SetInternalFieldCount(
          global_template->InternalFieldCount());

      // Migrate security handlers from global_template to
      // proxy_template.  Temporarily removing access check
      // information from the global template.
      if (!IsUndefined(global_constructor->GetAccessCheckInfo(), i_isolate)) {
        i::FunctionTemplateInfo::SetAccessCheckInfo(
            i_isolate, proxy_constructor,
            i::handle(global_constructor->GetAccessCheckInfo(), i_isolate));
        proxy_constructor->set_needs_access_check(
            global_constructor->needs_access_check());
        global_constructor->set_needs_access_check(false);
        i::FunctionTemplateInfo::SetAccessCheckInfo(
            i_isolate, global_constructor,
            i::ReadOnlyRoots(i_isolate).undefined_value_handle());
      }

      // Same for other interceptors. If the global constructor has
      // interceptors, we need to replace them temporarily with noop
      // interceptors, so the map is correctly marked as having interceptors,
      // but we don't invoke any.
      if (!IsUndefined(global_constructor->GetNamedPropertyHandler(),
                       i_isolate)) {
        named_interceptor =
            handle(global_constructor->GetNamedPropertyHandler(), i_isolate);
        i::FunctionTemplateInfo::SetNamedPropertyHandler(
            i_isolate, global_constructor,
            i::ReadOnlyRoots(i_isolate).noop_interceptor_info_handle());
      }
      if (!IsUndefined(global_constructor->GetIndexedPropertyHandler(),
                       i_isolate)) {
        indexed_interceptor =
            handle(global_constructor->GetIndexedPropertyHandler(), i_isolate);
        i::FunctionTemplateInfo::SetIndexedPropertyHandler(
            i_isolate, global_constructor,
            i::ReadOnlyRoots(i_isolate).noop_interceptor_info_handle());
      }
    }

    i::MaybeHandle<i::JSGlobalProxy> maybe_proxy;
    if (!maybe_global_proxy.IsEmpty()) {
      maybe_proxy = i::Cast<i::JSGlobalProxy>(
          Utils::OpenHandle(*maybe_global_proxy.ToLocalChecked()));
    }
    // Create the environment.
    InvokeBootstrapper<ObjectType> invoke;
    result = invoke.Invoke(i_isolate, maybe_proxy, proxy_template, extensions,
                           context_snapshot_index, embedder_fields_deserializer,
                           microtask_queue);

    // Restore the access check info and interceptors on the global template.
    if (!maybe_global_template.IsEmpty()) {
      DCHECK(!global_constructor.is_null());
      DCHECK(!proxy_constructor.is_null());
      i::FunctionTemplateInfo::SetAccessCheckInfo(
          i_isolate, global_constructor,
          i::handle(proxy_constructor->GetAccessCheckInfo(), i_isolate));
      global_constructor->set_needs_access_check(
          proxy_constructor->needs_access_check());
      i::FunctionTemplateInfo::SetNamedPropertyHandler(
          i_isolate, global_constructor, named_interceptor);
      i::FunctionTemplateInfo::SetIndexedPropertyHandler(
          i_isolate, global_constructor, indexed_interceptor);
    }
  }
  // Leave V8.

  return result;
}

Local<Context> NewContext(
    v8::Isolate* external_isolate, v8::ExtensionConfiguration* extensions,
    v8::MaybeLocal<ObjectTemplate> global_template,
    v8::MaybeLocal<Value> global_object, size_t context_snapshot_index,
    i::DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
    v8::MicrotaskQueue* microtask_queue) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(external_isolate);
  // TODO(jkummerow): This is for crbug.com/713699. Remove it if it doesn't
  // fail.
  // Sanity-check that the isolate is initialized and usable.
  CHECK(IsCode(i_isolate->builtins()->code(i::Builtin::kIllegal)));

  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.NewContext");
  API_RCS_SCOPE(i_isolate, Context, New);
  i::HandleScope scope(i_isolate);
  ExtensionConfiguration no_extensions;
  if (extensions == nullptr) extensions = &no_extensions;
  i::DirectHandle<i::NativeContext> env = CreateEnvironment<i::NativeContext>(
      i_isolate, extensions, global_template, global_object,
      context_snapshot_index, embedder_fields_deserializer, microtask_queue);
  if (env.is_null()) return Local<Context>();
  return Utils::ToLocal(scope.CloseAndEscape(env));
}

Local<Context> v8::Context::New(
    v8::Isolate* external_isolate, v8::ExtensionConfiguration* extensions,
    v8::MaybeLocal<ObjectTemplate> global_template,
    v8::MaybeLocal<Value> global_object,
    v8::DeserializeInternalFieldsCallback internal_fields_deserializer,
    v8::MicrotaskQueue* microtask_queue,
    v8::DeserializeContextDataCallback context_callback_deserializer,
    v8::DeserializeAPIWrapperCallback api_wrapper_deserializer) {
  return NewContext(
      external_isolate, extensions, global_template, global_object, 0,
      i::DeserializeEmbedderFieldsCallback(internal_fields_deserializer,
                                           context_callback_deserializer,
                                           api_wrapper_deserializer),
      microtask_queue);
}

MaybeLocal<Context> v8::Context::FromSnapshot(
    v8::Isolate* external_isolate, size_t context_snapshot_index,
    v8::DeserializeInternalFieldsCallback internal_fields_deserializer,
    v8::ExtensionConfiguration* extensions, MaybeLocal<Value> global_object,
    v8::MicrotaskQueue* microtask_queue,
    v8::DeserializeContextDataCallback context_callback_deserializer,
    v8::DeserializeAPIWrapperCallback api_wrapper_deserializer) {
  size_t index_including_default_context = context_snapshot_index + 1;
  if (!i::Snapshot::HasContextSnapshot(
          reinterpret_cast<i::Isolate*>(external_isolate),
          index_including_default_context)) {
    return MaybeLocal<Context>();
  }
  return NewContext(
      external_isolate, extensions, MaybeLocal<ObjectTemplate>(), global_object,
      index_including_default_context,
      i::DeserializeEmbedderFieldsCallback(internal_fields_deserializer,
                                           context_callback_deserializer,
                                           api_wrapper_deserializer),
      microtask_queue);
}

MaybeLocal<Object> v8::Context::NewRemoteContext(
    v8::Isolate* external_isolate, v8::Local<ObjectTemplate> global_template,
    v8::MaybeLocal<v8::Value> global_object) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(external_isolate);
  API_RCS_SCOPE(i_isolate, Context, NewRemoteContext);
  i::HandleScope scope(i_isolate);
  i::DirectHandle<i::FunctionTemplateInfo> global_constructor =
      EnsureConstructor(i_isolate, *global_template);
  Utils::ApiCheck(global_constructor->needs_access_check(),
                  "v8::Context::NewRemoteContext",
                  "Global template needs to have access checks enabled");
  i::DirectHandle<i::AccessCheckInfo> access_check_info(
      i::Cast<i::AccessCheckInfo>(global_constructor->GetAccessCheckInfo()),
      i_isolate);
  Utils::ApiCheck(
      access_check_info->named_interceptor() != i::Tagged<i::Object>(),
      "v8::Context::NewRemoteContext",
      "Global template needs to have access check handlers");
  i::DirectHandle<i::JSObject> global_proxy =
      CreateEnvironment<i::JSGlobalProxy>(
          i_isolate, nullptr, global_template, global_object, 0,
          i::DeserializeEmbedderFieldsCallback(), nullptr);
  if (global_proxy.is_null()) {
    if (i_isolate->has_exception()) i_isolate->clear_exception();
    return MaybeLocal<Object>();
  }
  return Utils::ToLocal(scope.CloseAndEscape(global_proxy));
}

void v8::Context::SetSecurityToken(Local<Value> token) {
  auto env = Utils::OpenDirectHandle(this);
  auto token_handle = Utils::OpenDirectHandle(*token);
  env->set_security_token(*token_handle);
}

void v8::Context::UseDefaultSecurityToken() {
  auto env = Utils::OpenDirectHandle(this);
  env->set_security_token(env->global_object());
}

Local<Value> v8::Context::GetSecurityToken() {
  auto env = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = env->GetIsolate();
  i::Tagged<i::Object> security_token = env->security_token();
  return Utils::ToLocal(i::direct_handle(security_token, i_isolate));
}

namespace {

bool MayContainObjectsToFreeze(i::InstanceType obj_type) {
  if (i::InstanceTypeChecker::IsString(obj_type)) return false;
  // SharedFunctionInfo is cross-context so it shouldn't be frozen.
  if (i::InstanceTypeChecker::IsSharedFunctionInfo(obj_type)) return false;
  return true;
}

bool RequiresEmbedderSupportToFreeze(i::InstanceType obj_type) {
  DCHECK(i::InstanceTypeChecker::IsJSReceiver(obj_type));

  return (i::InstanceTypeChecker::IsJSApiObject(obj_type) ||
          i::InstanceTypeChecker::IsJSExternalObject(obj_type) ||
          i::InstanceTypeChecker::IsJSAPIObjectWithEmbedderSlots(obj_type));
}

bool IsJSReceiverSafeToFreeze(i::InstanceType obj_type) {
  DCHECK(i::InstanceTypeChecker::IsJSReceiver(obj_type));

  switch (obj_type) {
    case i::JS_OBJECT_TYPE:
    case i::JS_GLOBAL_OBJECT_TYPE:
    case i::JS_GLOBAL_PROXY_TYPE:
    case i::JS_PRIMITIVE_WRAPPER_TYPE:
    case i::JS_FUNCTION_TYPE:
    /* Function types */
    case i::BIGINT64_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::BIGUINT64_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::FLOAT16_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::FLOAT32_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::FLOAT64_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::INT16_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::INT32_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::INT8_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::UINT16_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::UINT32_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::UINT8_CLAMPED_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::UINT8_TYPED_ARRAY_CONSTRUCTOR_TYPE:
    case i::JS_ARRAY_CONSTRUCTOR_TYPE:
    case i::JS_PROMISE_CONSTRUCTOR_TYPE:
    case i::JS_REG_EXP_CONSTRUCTOR_TYPE:
    case i::JS_CLASS_CONSTRUCTOR_TYPE:
    /* Prototype Types */
    case i::JS_ARRAY_ITERATOR_PROTOTYPE_TYPE:
    case i::JS_ITERATOR_PROTOTYPE_TYPE:
    case i::JS_MAP_ITERATOR_PROTOTYPE_TYPE:
    case i::JS_OBJECT_PROTOTYPE_TYPE:
    case i::JS_PROMISE_PROTOTYPE_TYPE:
    case i::JS_REG_EXP_PROTOTYPE_TYPE:
    case i::JS_SET_ITERATOR_PROTOTYPE_TYPE:
    case i::JS_SET_PROTOTYPE_TYPE:
    case i::JS_STRING_ITERATOR_PROTOTYPE_TYPE:
    case i::JS_TYPED_ARRAY_PROTOTYPE_TYPE:
    /* */
    case i::JS_ARRAY_TYPE:
      return true;
#if V8_ENABLE_WEBASSEMBLY
    case i::WASM_ARRAY_TYPE:
    case i::WASM_STRUCT_TYPE:
    case i::WASM_TAG_OBJECT_TYPE:
#endif  // V8_ENABLE_WEBASSEMBLY
    case i::JS_PROXY_TYPE:
      return true;
    // These types are known not to freeze.
    case i::JS_MAP_KEY_ITERATOR_TYPE:
    case i::JS_MAP_KEY_VALUE_ITERATOR_TYPE:
    case i::JS_MAP_VALUE_ITERATOR_TYPE:
    case i::JS_SET_KEY_VALUE_ITERATOR_TYPE:
    case i::JS_SET_VALUE_ITERATOR_TYPE:
    case i::JS_GENERATOR_OBJECT_TYPE:
    case i::JS_ASYNC_FUNCTION_OBJECT_TYPE:
    case i::JS_ASYNC_GENERATOR_OBJECT_TYPE:
    case i::JS_ARRAY_ITERATOR_TYPE: {
      return false;
    }
    default:
      // TODO(behamilton): Handle any types that fall through here.
      return false;
  }
}

class ObjectVisitorDeepFreezer : i::ObjectVisitor {
 public:
  explicit ObjectVisitorDeepFreezer(i::Isolate* isolate,
                                    Context::DeepFreezeDelegate* delegate)
      : isolate_(isolate), delegate_(delegate) {}

  bool DeepFreeze(i::DirectHandle<i::Context> context) {
    bool success = VisitObject(i::Cast<i::HeapObject>(*context));
    if (success) {
      success = InstantiateAndVisitLazyAccessorPairs();
    }
    DCHECK_EQ(success, !error_.has_value());
    if (!success) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate_, NewTypeError(error_->msg_id, error_->name), false);
    }
    for (const auto& obj : objects_to_freeze_) {
      MAYBE_RETURN_ON_EXCEPTION_VALUE(
          isolate_,
          i::JSReceiver::SetIntegrityLevel(isolate_, obj, i::FROZEN,
                                           i::kThrowOnError),
          false);
    }
    return true;
  }

  void VisitPointers(i::Tagged<i::HeapObject> host, i::ObjectSlot start,
                     i::ObjectSlot end) final {
    VisitPointersImpl(start, end);
  }
  void VisitPointers(i::Tagged<i::HeapObject> host, i::MaybeObjectSlot start,
                     i::MaybeObjectSlot end) final {
    VisitPointersImpl(start, end);
  }
  void VisitMapPointer(i::Tagged<i::HeapObject> host) final {
    VisitPointer(host, host->map_slot());
  }
  void VisitInstructionStreamPointer(i::Tagged<i::Code> host,
                                     i::InstructionStreamSlot slot) final {}
  void VisitCustomWeakPointers(i::Tagged<i::HeapObject> host,
                               i::ObjectSlot start, i::ObjectSlot end) final {}

 private:
  struct ErrorInfo {
    i::MessageTemplate msg_id;
    i::Handle<i::String> name;
  };

  template <typename TSlot>
  void VisitPointersImpl(TSlot start, TSlot end) {
    for (TSlot current = start; current < end; ++current) {
      typename TSlot::TObject object = current.load(isolate_);
      i::Tagged<i::HeapObject> heap_object;
      if (object.GetHeapObjectIfStrong(&heap_object)) {
        if (!VisitObject(heap_object)) {
          return;
        }
      }
    }
  }

  bool FreezeEmbedderObjectAndVisitChildren(i::Handle<i::JSObject> obj) {
    DCHECK(delegate_);
    LocalVector<Object> children(reinterpret_cast<Isolate*>(isolate_));
    if (!delegate_->FreezeEmbedderObjectAndGetChildren(Utils::ToLocal(obj),
                                                       children)) {
      return false;
    }
    for (auto child : children) {
      if (!VisitObject(
              *Utils::OpenDirectHandle<Object, i::JSReceiver>(child))) {
        return false;
      }
    }
    return true;
  }

  bool VisitObject(i::Tagged<i::HeapObject> obj) {
    DCHECK(!obj.is_null());
    if (error_.has_value()) {
      return false;
    }

    i::DisallowGarbageCollection no_gc;
    i::InstanceType obj_type = obj->map()->instance_type();

    // Skip common types that can't contain items to freeze.
    if (!MayContainObjectsToFreeze(obj_type)) {
      return true;
    }

    if (!done_list_.insert(obj).second) {
      // If we couldn't insert (because it is already in the set) then we're
      // done.
      return true;
    }

    if (i::InstanceTypeChecker::IsAccessorPair(obj_type)) {
      // For AccessorPairs we need to ensure that the functions they point to
      // have been instantiated into actual JavaScript objects that can be
      // frozen. If they haven't then we need to save them to instantiate
      // (and recurse) before freezing.
      i::Tagged<i::AccessorPair> accessor_pair = i::Cast<i::AccessorPair>(obj);
      if (i::IsFunctionTemplateInfo(accessor_pair->getter()) ||
          IsFunctionTemplateInfo(accessor_pair->setter())) {
        i::Handle<i::AccessorPair> lazy_accessor_pair(accessor_pair, isolate_);
        lazy_accessor_pairs_to_freeze_.push_back(lazy_accessor_pair);
      }
    } else if (i::InstanceTypeChecker::IsContext(obj_type)) {
      // For contexts we need to ensure that all accessible locals are const.
      // If not they could be replaced to bypass freezing.
      i::Tagged<i::ScopeInfo> scope_info =
          i::Cast<i::Context>(obj)->scope_info();
      for (auto it : i::ScopeInfo::IterateLocalNames(scope_info, no_gc)) {
        if (!IsImmutableLexicalVariableMode(
                scope_info->ContextLocalMode(it->index()))) {
          DCHECK(!error_.has_value());
          error_ = ErrorInfo{i::MessageTemplate::kCannotDeepFreezeValue,
                             i::handle(it->name(), isolate_)};
          return false;
        }
      }
    } else if (i::InstanceTypeChecker::IsJSReceiver(obj_type)) {
      i::Handle<i::JSReceiver> receiver(i::Cast<i::JSReceiver>(obj), isolate_);
      if (RequiresEmbedderSupportToFreeze(obj_type)) {
        auto js_obj = i::Cast<i::JSObject>(receiver);

        // External objects don't have slots but still need to be processed by
        // the embedder.
        if (i::InstanceTypeChecker::IsJSExternalObject(obj_type) ||
            js_obj->GetEmbedderFieldCount() > 0) {
          if (!delegate_) {
            DCHECK(!error_.has_value());
            error_ = ErrorInfo{i::MessageTemplate::kCannotDeepFreezeObject,
                               i::handle(receiver->class_name(), isolate_)};
            return false;
          }

          // Handle embedder specific types and any v8 children it wants to
          // freeze.
          if (!FreezeEmbedderObjectAndVisitChildren(js_obj)) {
            return false;
          }
        } else {
          DCHECK_EQ(js_obj->GetEmbedderFieldCount(), 0);
        }
      } else {
        DCHECK_IMPLIES(
            i::InstanceTypeChecker::IsJSObject(obj_type),
            i::Cast<i::JSObject>(*receiver)->GetEmbedderFieldCount() == 0);
        if (!IsJSReceiverSafeToFreeze(obj_type)) {
          DCHECK(!error_.has_value());
          error_ = ErrorInfo{i::MessageTemplate::kCannotDeepFreezeObject,
                             i::handle(receiver->class_name(), isolate_)};
          return false;
        }
      }

      // Save this to freeze after we are done. Freezing triggers garbage
      // collection which doesn't work well with this visitor pattern, so we
      // delay it until after.
      objects_to_freeze_.push_back(receiver);

    } else {
      DCHECK(!i::InstanceTypeChecker::IsAccessorPair(obj_type));
      DCHECK(!i::InstanceTypeChecker::IsContext(obj_type));
      DCHECK(!i::InstanceTypeChecker::IsJSReceiver(obj_type));
    }

    DCHECK(!error_.has_value());
    i::VisitObject(isolate_, obj, this);
    // Iterate sets error_ on failure. We should propagate errors.
    return !error_.has_value();
  }

  bool InstantiateAndVisitLazyAccessorPairs() {
    i::Handle<i::NativeContext> native_context = isolate_->native_context();

    std::vector<i::Handle<i::AccessorPair>> lazy_accessor_pairs_to_freeze;
    std::swap(lazy_accessor_pairs_to_freeze, lazy_accessor_pairs_to_freeze_);

    for (const auto& accessor_pair : lazy_accessor_pairs_to_freeze) {
      i::AccessorPair::GetComponent(isolate_, native_context, accessor_pair,
                                    i::ACCESSOR_GETTER);
      i::AccessorPair::GetComponent(isolate_, native_context, accessor_pair,
                                    i::ACCESSOR_SETTER);
      VisitObject(*accessor_pair);
    }
    // Ensure no new lazy accessor pairs were discovered.
    CHECK_EQ(lazy_accessor_pairs_to_freeze_.size(), 0);
    return true;
  }

  i::Isolate* isolate_;
  Context::DeepFreezeDelegate* delegate_;
  std::unordered_set<i::Tagged<i::Object>, i::Object::Hasher> done_list_;
  std::vector<i::Handle<i::JSReceiver>> objects_to_freeze_;
  std::vector<i::Handle<i::AccessorPair>> lazy_accessor_pairs_to_freeze_;
  std::optional<ErrorInfo> error_;
};

}  // namespace

Maybe<void> Context::DeepFreeze(DeepFreezeDelegate* delegate) {
  auto env = Utils::OpenHandle(this);
  i::Isolate* i_isolate = env->GetIsolate();

  // TODO(behamilton): Incorporate compatibility improvements similar to NodeJS:
  // https://github.com/nodejs/node/blob/main/lib/internal/freeze_intrinsics.js
  // These need to be done before freezing.

  Local<Context> context = Utils::ToLocal(env);
  ENTER_V8_NO_SCRIPT(i_isolate, context, Context, DeepFreeze, i::HandleScope);
  ObjectVisitorDeepFreezer vfreezer(i_isolate, delegate);
  has_exception = !vfreezer.DeepFreeze(env);

  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(void);
  return JustVoid();
}

v8::Isolate* Context::GetIsolate() {
  return reinterpret_cast<Isolate*>(
      Utils::OpenDirectHandle(this)->GetIsolate());
}

v8::MicrotaskQueue* Context::GetMicrotaskQueue() {
  auto env = Utils::OpenDirectHandle(this);
  Utils::ApiCheck(i::IsNativeContext(*env), "v8::Context::GetMicrotaskQueue",
                  "Must be called on a native context");
  return env->microtask_queue();
}

void Context::SetMicrotaskQueue(v8::MicrotaskQueue* queue) {
  auto context = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();
  Utils::ApiCheck(i::IsNativeContext(*context),
                  "v8::Context::SetMicrotaskQueue",
                  "Must be called on a native context");
  i::HandleScopeImplementer* impl = i_isolate->handle_scope_implementer();
  Utils::ApiCheck(!context->microtask_queue()->IsRunningMicrotasks(),
                  "v8::Context::SetMicrotaskQueue",
                  "Must not be running microtasks");
  Utils::ApiCheck(context->microtask_queue()->GetMicrotasksScopeDepth() == 0,
                  "v8::Context::SetMicrotaskQueue",
                  "Must not have microtask scope pushed");
  Utils::ApiCheck(impl->EnteredContextCount() == 0,
                  "v8::Context::SetMicrotaskQueue()",
                  "Cannot set Microtask Queue with an entered context");
  context->set_microtask_queue(i_isolate,
                               static_cast<const i::MicrotaskQueue*>(queue));
}

v8::Local<v8::Object> Context::Global() {
  auto context = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();
  i::DirectHandle<i::JSGlobalProxy> global(context->global_proxy(), i_isolate);
  // TODO(chromium:324812): This should always return the global proxy
  // but can't presently as calls to GetPrototype will return the wrong result.
  if (global->IsDetachedFrom(context->global_object())) {
    i::DirectHandle<i::JSObject> result(context->global_object(), i_isolate);
    return Utils::ToLocal(result);
  }
  return Utils::ToLocal(i::Cast<i::JSObject>(global));
}

void Context::DetachGlobal() {
  auto context = Utils::OpenHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i_isolate->DetachGlobal(context);
}

Local<v8::Object> Context::GetExtrasBindingObject() {
  auto context = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();
  return Utils::ToLocal(
      i::direct_handle(context->extras_binding_object(), i_isolate));
}

void Context::AllowCodeGenerationFromStrings(bool allow) {
  auto context = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  context->set_allow_code_gen_from_strings(
      i::ReadOnlyRoots(i_isolate).boolean_value(allow));
}

bool Context::IsCodeGenerationFromStringsAllowed() const {
  auto context = Utils::OpenDirectHandle(this);
  return !IsFalse(context->allow_code_gen_from_strings(),
                  context->GetIsolate());
}

void Context::SetErrorMessageForCodeGenerationFromStrings(Local<String> error) {
  auto context = Utils::OpenDirectHandle(this);
  auto error_handle = Utils::OpenDirectHandle(*error);
  context->set_error_message_for_code_gen_from_strings(*error_handle);
}

void Context::SetErrorMessageForWasmCodeGeneration(Local<String> error) {
  auto context = Utils::OpenDirectHandle(this);
  auto error_handle = Utils::OpenDirectHandle(*error);
  context->set_error_message_for_wasm_code_gen(*error_handle);
}

void Context::SetAbortScriptExecution(
    Context::AbortScriptExecutionCallback callback) {
  auto context = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();
  if (callback == nullptr) {
    context->set_script_execution_callback(
        i::ReadOnlyRoots(i_isolate).undefined_value());
  } else {
    SET_FIELD_WRAPPED(i_isolate, context, set_script_execution_callback,
                      callback, internal::kApiAbortScriptExecutionCallbackTag);
  }
}

void v8::Context::SetPromiseHooks(Local<Function> init_hook,
                                  Local<Function> before_hook,
                                  Local<Function> after_hook,
                                  Local<Function> resolve_hook) {
#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
  auto context = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();

  auto undefined = i_isolate->factory()->undefined_value();
  i::DirectHandle<i::Object> init = undefined;
  i::DirectHandle<i::Object> before = undefined;
  i::DirectHandle<i::Object> after = undefined;
  i::DirectHandle<i::Object> resolve = undefined;

  bool has_hook = false;

  if (!init_hook.IsEmpty()) {
    init = Utils::OpenDirectHandle(*init_hook);
    has_hook = true;
  }
  if (!before_hook.IsEmpty()) {
    before = Utils::OpenDirectHandle(*before_hook);
    has_hook = true;
  }
  if (!after_hook.IsEmpty()) {
    after = Utils::OpenDirectHandle(*after_hook);
    has_hook = true;
  }
  if (!resolve_hook.IsEmpty()) {
    resolve = Utils::OpenDirectHandle(*resolve_hook);
    has_hook = true;
  }

  i_isolate->SetHasContextPromiseHooks(has_hook);

  context->native_context()->set_promise_hook_init_function(*init);
  context->native_context()->set_promise_hook_before_function(*before);
  context->native_context()->set_promise_hook_after_function(*after);
  context->native_context()->set_promise_hook_resolve_function(*resolve);
#else   // V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
  Utils::ApiCheck(false, "v8::Context::SetPromiseHook",
                  "V8 was compiled without JavaScript Promise hooks");
#endif  // V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
}

bool Context::HasTemplateLiteralObject(Local<Value> object) {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::Object> i_object = *Utils::OpenDirectHandle(*object);
  if (!IsJSArray(i_object)) return false;
  return Utils::OpenDirectHandle(this)
      ->native_context()
      ->HasTemplateLiteralObject(i::Cast<i::JSArray>(i_object));
}

MaybeLocal<Context> metrics::Recorder::GetContext(
    Isolate* v8_isolate, metrics::Recorder::ContextId id) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  return i_isolate->GetContextFromRecorderContextId(id);
}

metrics::Recorder::ContextId metrics::Recorder::GetContextId(
    Local<Context> context) {
  auto i_context = Utils::OpenDirectHandle(*context);
  i::Isolate* i_isolate = i_context->GetIsolate();
  return i_isolate->GetOrRegisterRecorderContextId(
      handle(i_context->native_context(), i_isolate));
}

metrics::LongTaskStats metrics::LongTaskStats::Get(v8::Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  return *i_isolate->GetCurrentLongTaskStats();
}

namespace {
i::ValueHelper::InternalRepresentationType GetSerializedDataFromFixedArray(
    i::Isolate* i_isolate, i::Tagged<i::FixedArray> list, size_t index) {
  if (index < static_cast<size_t>(list->length())) {
    int int_index = static_cast<int>(index);
    i::Tagged<i::Object> object = list->get(int_index);
    if (!IsTheHole(object, i_isolate)) {
      list->set_the_hole(i_isolate, int_index);
      // Shrink the list so that the last element is not the hole (unless it's
      // the first element, because we don't want to end up with a non-canonical
      // empty FixedArray).
      int last = list->length() - 1;
      while (last >= 0 && list->is_the_hole(i_isolate, last)) last--;
      if (last != -1) list->RightTrim(i_isolate, last + 1);
      return i::Handle<i::Object>(object, i_isolate).repr();
    }
  }
  return i::ValueHelper::kEmpty;
}
}  // anonymous namespace

i::ValueHelper::InternalRepresentationType Context::GetDataFromSnapshotOnce(
    size_t index) {
  auto context = Utils::OpenHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();
  auto list = i::Cast<i::FixedArray>(context->serialized_objects());
  return GetSerializedDataFromFixedArray(i_isolate, list, index);
}

MaybeLocal<v8::Object> ObjectTemplate::NewInstance(Local<Context> context) {
  PREPARE_FOR_EXECUTION(context, ObjectTemplate, NewInstance);
  auto self = Utils::OpenHandle(this);
  Local<Object> result;
  has_exception = !ToLocal<Object>(
      i::ApiNatives::InstantiateObject(i_isolate, self), &result);
  RETURN_ON_FAILED_EXECUTION(Object);
  RETURN_ESCAPED(result);
}

void v8::ObjectTemplate::CheckCast(Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsObjectTemplateInfo(*obj), "v8::ObjectTemplate::Cast",
                  "Value is not an ObjectTemplate");
}

void v8::DictionaryTemplate::CheckCast(Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsDictionaryTemplateInfo(*obj),
                  "v8::DictionaryTemplate::Cast",
                  "Value is not an DictionaryTemplate");
}

void v8::FunctionTemplate::CheckCast(Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsFunctionTemplateInfo(*obj), "v8::FunctionTemplate::Cast",
                  "Value is not a FunctionTemplate");
}

void v8::Signature::CheckCast(Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsFunctionTemplateInfo(*obj), "v8::Signature::Cast",
                  "Value is not a Signature");
}

MaybeLocal<v8::Function> FunctionTemplate::GetFunction(Local<Context> context) {
  PREPARE_FOR_EXECUTION(context, FunctionTemplate, GetFunction);
  auto self = Utils::OpenHandle(this);
  Local<Function> result;
  has_exception =
      !ToLocal<Function>(i::ApiNatives::InstantiateFunction(
                             i_isolate, i_isolate->native_context(), self),
                         &result);
  RETURN_ON_FAILED_EXECUTION(Function);
  RETURN_ESCAPED(result);
}

MaybeLocal<v8::Object> FunctionTemplate::NewRemoteInstance() {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolateChecked();
  API_RCS_SCOPE(i_isolate, FunctionTemplate, NewRemoteInstance);
  i::HandleScope scope(i_isolate);
  i::DirectHandle<i::FunctionTemplateInfo> constructor =
      EnsureConstructor(i_isolate, *InstanceTemplate());
  Utils::ApiCheck(constructor->needs_access_check(),
                  "v8::FunctionTemplate::NewRemoteInstance",
                  "InstanceTemplate needs to have access checks enabled");
  i::DirectHandle<i::AccessCheckInfo> access_check_info(
      i::Cast<i::AccessCheckInfo>(constructor->GetAccessCheckInfo()),
      i_isolate);
  Utils::ApiCheck(
      access_check_info->named_interceptor() != i::Tagged<i::Object>(),
      "v8::FunctionTemplate::NewRemoteInstance",
      "InstanceTemplate needs to have access check handlers");
  i::Handle<i::JSObject> object;
  if (!i::ApiNatives::InstantiateRemoteObject(
           Utils::OpenHandle(*InstanceTemplate()))
           .ToHandle(&object)) {
    return MaybeLocal<Object>();
  }
  return Utils::ToLocal(scope.CloseAndEscape(object));
}

bool FunctionTemplate::HasInstance(v8::Local<v8::Value> value) {
  auto self = Utils::OpenDirectHandle(this);
  auto obj = Utils::OpenDirectHandle(*value);
  if (i::IsJSObject(*obj) && self->IsTemplateFor(i::Cast<i::JSObject>(*obj))) {
    return true;
  }
  if (i::IsJSGlobalProxy(*obj)) {
    // If it's a global proxy, then test with the global object. Note that the
    // inner global object may not necessarily be a JSGlobalObject.
    auto jsobj = i::Cast<i::JSObject>(*obj);
    i::PrototypeIterator iter(jsobj->GetIsolate(), jsobj->map());
    // The global proxy should always have a prototype, as it is a bug to call
    // this on a detached JSGlobalProxy.
    DCHECK(!iter.IsAtEnd());
    return self->IsTemplateFor(iter.GetCurrent<i::JSObject>());
  }
  return false;
}

bool FunctionTemplate::IsLeafTemplateForApiObject(
    v8::Local<v8::Value> value) const {
  i::DisallowGarbageCollection no_gc;
  auto self = Utils::OpenDirectHandle(this);
  i::Tagged<i::Object> object = *Utils::OpenDirectHandle(*value);
  return self->IsLeafTemplateForApiObject(object);
}

Local<External> v8::External::New(Isolate* v8_isolate, void* value) {
  static_assert(sizeof(value) == sizeof(i::Address));
  // Nullptr is not allowed here because serialization/deserialization of
  // nullptr external api references is not possible as nullptr is used as an
  // external_references table terminator, see v8::SnapshotCreator()
  // constructors.
  DCHECK_NOT_NULL(value);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, External, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::JSObject> external = i_isolate->factory()->NewExternal(value);
  return Utils::ExternalToLocal(external);
}

void* External::Value() const {
  return i::Cast<i::JSExternalObject>(*Utils::OpenDirectHandle(this))->value();
}

// anonymous namespace for string creation helper functions
namespace {

inline int StringLength(const char* string) {
  size_t len = strlen(string);
  CHECK_GE(i::kMaxInt, len);
  return static_cast<int>(len);
}

inline int StringLength(const uint8_t* string) {
  return StringLength(reinterpret_cast<const char*>(string));
}

inline int StringLength(const uint16_t* string) {
  size_t length = 0;
  while (string[length] != '\0') length++;
  CHECK_GE(i::kMaxInt, length);
  return static_cast<int>(length);
}

V8_WARN_UNUSED_RESULT
inline i::MaybeHandle<i::String> NewString(i::Factory* factory,
                                           NewStringType type,
                                           base::Vector<const char> string) {
  if (type == NewStringType::kInternalized) {
    return factory->InternalizeUtf8String(string);
  }
  return factory->NewStringFromUtf8(string);
}

V8_WARN_UNUSED_RESULT
inline i::MaybeHandle<i::String> NewString(i::Factory* factory,
                                           NewStringType type,
                                           base::Vector<const uint8_t> string) {
  if (type == NewStringType::kInternalized) {
    return factory->InternalizeString(string);
  }
  return factory->NewStringFromOneByte(string);
}

V8_WARN_UNUSED_RESULT
inline i::MaybeHandle<i::String> NewString(
    i::Factory* factory, NewStringType type,
    base::Vector<const uint16_t> string) {
  if (type == NewStringType::kInternalized) {
    return factory->InternalizeString(string);
  }
  return factory->NewStringFromTwoByte(string);
}

static_assert(v8::String::kMaxLength == i::String::kMaxLength);

}  // anonymous namespace

// TODO(dcarney): throw a context free exception.
#define NEW_STRING(v8_isolate, class_name, function_name, Char, data, type,   \
                   length)                                                    \
  MaybeLocal<String> result;                                                  \
  if (length == 0) {                                                          \
    result = String::Empty(v8_isolate);                                       \
  } else if (length > 0 &&                                                    \
             static_cast<uint32_t>(length) > i::String::kMaxLength) {         \
    result = MaybeLocal<String>();                                            \
  } else {                                                                    \
    i::Isolate* i_isolate = reinterpret_cast<internal::Isolate*>(v8_isolate); \
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);                               \
    API_RCS_SCOPE(i_isolate, class_name, function_name);                      \
    if (length < 0) length = StringLength(data);                              \
    i::Handle<i::String> handle_result =                                      \
        NewString(i_isolate->factory(), type,                                 \
                  base::Vector<const Char>(data, length))                     \
            .ToHandleChecked();                                               \
    result = Utils::ToLocal(handle_result);                                   \
  }

Local<String> String::NewFromUtf8Literal(Isolate* v8_isolate,
                                         const char* literal,
                                         NewStringType type, int length) {
  DCHECK_LE(length, i::String::kMaxLength);
  i::Isolate* i_isolate = reinterpret_cast<internal::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  API_RCS_SCOPE(i_isolate, String, NewFromUtf8Literal);
  i::Handle<i::String> handle_result =
      NewString(i_isolate->factory(), type,
                base::Vector<const char>(literal, length))
          .ToHandleChecked();
  return Utils::ToLocal(handle_result);
}

MaybeLocal<String> String::NewFromUtf8(Isolate* v8_isolate, const char* data,
                                       NewStringType type, int length) {
  NEW_STRING(v8_isolate, String, NewFromUtf8, char, data, type, length);
  return result;
}

MaybeLocal<String> String::NewFromOneByte(Isolate* v8_isolate,
                                          const uint8_t* data,
                                          NewStringType type, int length) {
  NEW_STRING(v8_isolate, String, NewFromOneByte, uint8_t, data, type, length);
  return result;
}

MaybeLocal<String> String::NewFromTwoByte(Isolate* v8_isolate,
                                          const uint16_t* data,
                                          NewStringType type, int length) {
  NEW_STRING(v8_isolate, String, NewFromTwoByte, uint16_t, data, type, length);
  return result;
}

Local<String> v8::String::Concat(Isolate* v8_isolate, Local<String> left,
                                 Local<String> right) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto left_string = Utils::OpenHandle(*left);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  API_RCS_SCOPE(i_isolate, String, Concat);
  auto right_string = Utils::OpenHandle(*right);
  // If we are steering towards a range error, do not wait for the error to be
  // thrown, and return the null handle instead.
  if (left_string->length() + right_string->length() > i::String::kMaxLength) {
    return Local<String>();
  }
  i::Handle<i::String> result = i_isolate->factory()
                                    ->NewConsString(left_string, right_string)
                                    .ToHandleChecked();
  return Utils::ToLocal(result);
}

MaybeLocal<String> v8::String::NewExternalTwoByte(
    Isolate* v8_isolate, v8::String::ExternalStringResource* resource) {
  CHECK(resource && resource->data());
  // TODO(dcarney): throw a context free exception.
  if (resource->length() > static_cast<size_t>(i::String::kMaxLength)) {
    return MaybeLocal<String>();
  }
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  API_RCS_SCOPE(i_isolate, String, NewExternalTwoByte);
  if (resource->length() > 0) {
    i::Handle<i::String> string = i_isolate->factory()
                                      ->NewExternalStringFromTwoByte(resource)
                                      .ToHandleChecked();
    return Utils::ToLocal(string);
  } else {
    // The resource isn't going to be used, free it immediately.
    resource->Unaccount(v8_isolate);
    resource->Dispose();
    return Utils::ToLocal(i_isolate->factory()->empty_string());
  }
}

MaybeLocal<String> v8::String::NewExternalOneByte(
    Isolate* v8_isolate, v8::String::ExternalOneByteStringResource* resource) {
  CHECK_NOT_NULL(resource);
  // TODO(dcarney): throw a context free exception.
  if (resource->length() > static_cast<size_t>(i::String::kMaxLength)) {
    return MaybeLocal<String>();
  }
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  API_RCS_SCOPE(i_isolate, String, NewExternalOneByte);
  if (resource->length() == 0) {
    // The resource isn't going to be used, free it immediately.
    resource->Unaccount(v8_isolate);
    resource->Dispose();
    return Utils::ToLocal(i_isolate->factory()->empty_string());
  }
  CHECK_NOT_NULL(resource->data());
  i::Handle<i::String> string = i_isolate->factory()
                                    ->NewExternalStringFromOneByte(resource)
                                    .ToHandleChecked();
  return Utils::ToLocal(string);
}

bool v8::String::MakeExternal(v8::String::ExternalStringResource* resource) {
  v8::Isolate* isolate = reinterpret_cast<v8::Isolate*>(i::Isolate::Current());
  return MakeExternal(isolate, resource);
}

bool v8::String::MakeExternal(Isolate* isolate,
                              v8::String::ExternalStringResource* resource) {
  i::DisallowGarbageCollection no_gc;

  i::Tagged<i::String> obj = *Utils::OpenDirectHandle(this);

  if (i::IsThinString(obj)) {
    obj = i::Cast<i::ThinString>(obj)->actual();
  }

  if (!obj->SupportsExternalization(Encoding::TWO_BYTE_ENCODING)) {
    return false;
  }

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);

  CHECK(resource && resource->data());

  bool result = obj->MakeExternal(i_isolate, resource);
  DCHECK_IMPLIES(result, HasExternalStringResource(obj));
  return result;
}

bool v8::String::MakeExternal(
    v8::String::ExternalOneByteStringResource* resource) {
  v8::Isolate* isolate = reinterpret_cast<v8::Isolate*>(i::Isolate::Current());
  return MakeExternal(isolate, resource);
}

bool v8::String::MakeExternal(
    Isolate* isolate, v8::String::ExternalOneByteStringResource* resource) {
  i::DisallowGarbageCollection no_gc;

  i::Tagged<i::String> obj = *Utils::OpenDirectHandle(this);

  if (i::IsThinString(obj)) {
    obj = i::Cast<i::ThinString>(obj)->actual();
  }

  if (!obj->SupportsExternalization(Encoding::ONE_BYTE_ENCODING)) {
    return false;
  }

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);

  CHECK(resource && resource->data());

  bool result = obj->MakeExternal(i_isolate, resource);
  DCHECK_IMPLIES(result, HasExternalStringResource(obj));
  return result;
}

bool v8::String::CanMakeExternal(Encoding encoding) const {
  i::Tagged<i::String> obj = *Utils::OpenDirectHandle(this);

  return obj->SupportsExternalization(encoding);
}

bool v8::String::StringEquals(Local<String> that) const {
  auto self = Utils::OpenDirectHandle(this);
  auto other = Utils::OpenDirectHandle(*that);
  return self->Equals(*other);
}

Isolate* v8::Object::GetIsolate() {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  return reinterpret_cast<Isolate*>(i_isolate);
}

Local<v8::Object> v8::Object::New(Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, Object, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::JSObject> obj =
      i_isolate->factory()->NewJSObject(i_isolate->object_function());
  return Utils::ToLocal(obj);
}

namespace {

// TODO(v8:7569): This is a workaround for the Handle vs MaybeHandle difference
// in the return types of the different Add functions:
// OrderedNameDictionary::Add returns MaybeHandle, NameDictionary::Add returns
// Handle.
template <typename T>
i::Handle<T> ToHandle(i::Handle<T> h) {
  return h;
}
template <typename T>
i::Handle<T> ToHandle(i::MaybeHandle<T> h) {
  return h.ToHandleChecked();
}

#ifdef V8_ENABLE_DIRECT_HANDLE
template <typename T>
i::DirectHandle<T> ToHandle(i::DirectHandle<T> h) {
  return h;
}
template <typename T>
i::DirectHandle<T> ToHandle(i::MaybeDirectHandle<T> h) {
  return h.ToHandleChecked();
}
#endif

template <typename Dictionary>
void AddPropertiesAndElementsToObject(i::Isolate* i_isolate,
                                      i::Handle<Dictionary>& properties,
                                      i::Handle<i::FixedArrayBase>& elements,
                                      Local<Name>* names, Local<Value>* values,
                                      size_t length) {
  for (size_t i = 0; i < length; ++i) {
    auto name = Utils::OpenHandle(*names[i]);
    auto value = Utils::OpenHandle(*values[i]);

    // See if the {name} is a valid array index, in which case we need to
    // add the {name}/{value} pair to the {elements}, otherwise they end
    // up in the {properties} backing store.
    uint32_t index;
    if (name->AsArrayIndex(&index)) {
      // If this is the first element, allocate a proper
      // dictionary elements backing store for {elements}.
      if (!IsNumberDictionary(*elements)) {
        elements =
            i::NumberDictionary::New(i_isolate, static_cast<int>(length));
      }
      elements = i::NumberDictionary::Set(
          i_isolate, i::Cast<i::NumberDictionary>(elements), index, value);
    } else {
      // Internalize the {name} first.
      name = i_isolate->factory()->InternalizeName(name);
      i::InternalIndex const entry = properties->FindEntry(i_isolate, name);
      if (entry.is_not_found()) {
        // Add the {name}/{value} pair as a new entry.
        properties = ToHandle(Dictionary::Add(
            i_isolate, properties, name, value, i::PropertyDetails::Empty()));
      } else {
        // Overwrite the {entry} with the {value}.
        properties->ValueAtPut(entry, *value);
      }
    }
  }
}

}  // namespace

Local<v8::Object> v8::Object::New(Isolate* v8_isolate,
                                  Local<Value> prototype_or_null,
                                  Local<Name>* names, Local<Value>* values,
                                  size_t length) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::Handle<i::JSPrototype> proto;
  if (!Utils::ApiCheck(
          i::TryCast(Utils::OpenHandle(*prototype_or_null), &proto),
          "v8::Object::New", "prototype must be null or object")) {
    return Local<v8::Object>();
  }
  API_RCS_SCOPE(i_isolate, Object, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);

  i::Handle<i::FixedArrayBase> elements =
      i_isolate->factory()->empty_fixed_array();

  // We assume that this API is mostly used to create objects with named
  // properties, and so we default to creating a properties backing store
  // large enough to hold all of them, while we start with no elements
  // (see http://bit.ly/v8-fast-object-create-cpp for the motivation).
  if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    i::Handle<i::SwissNameDictionary> properties =
        i_isolate->factory()->NewSwissNameDictionary(static_cast<int>(length));
    AddPropertiesAndElementsToObject(i_isolate, properties, elements, names,
                                     values, length);
    i::Handle<i::JSObject> obj =
        i_isolate->factory()->NewSlowJSObjectWithPropertiesAndElements(
            proto, properties, elements);
    return Utils::ToLocal(obj);
  } else {
    i::Handle<i::NameDictionary> properties =
        i::NameDictionary::New(i_isolate, static_cast<int>(length));
    AddPropertiesAndElementsToObject(i_isolate, properties, elements, names,
                                     values, length);
    i::Handle<i::JSObject> obj =
        i_isolate->factory()->NewSlowJSObjectWithPropertiesAndElements(
            proto, properties, elements);
    return Utils::ToLocal(obj);
  }
}

Local<v8::Value> v8::NumberObject::New(Isolate* v8_isolate, double value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, NumberObject, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Object> number = i_isolate->factory()->NewNumber(value);
  i::Handle<i::Object> obj =
      i::Object::ToObject(i_isolate, number).ToHandleChecked();
  return Utils::ToLocal(obj);
}

double v8::NumberObject::ValueOf() const {
  auto obj = Utils::OpenDirectHandle(this);
  auto js_primitive_wrapper = i::Cast<i::JSPrimitiveWrapper>(obj);
  API_RCS_SCOPE(js_primitive_wrapper->GetIsolate(), NumberObject, NumberValue);
  return i::Object::NumberValue(
      i::Cast<i::Number>(js_primitive_wrapper->value()));
}

Local<v8::Value> v8::BigIntObject::New(Isolate* v8_isolate, int64_t value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, BigIntObject, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Object> bigint = i::BigInt::FromInt64(i_isolate, value);
  i::Handle<i::Object> obj =
      i::Object::ToObject(i_isolate, bigint).ToHandleChecked();
  return Utils::ToLocal(obj);
}

Local<v8::BigInt> v8::BigIntObject::ValueOf() const {
  auto obj = Utils::OpenHandle(this);
  auto js_primitive_wrapper = i::Cast<i::JSPrimitiveWrapper>(obj);
  i::Isolate* i_isolate = js_primitive_wrapper->GetIsolate();
  API_RCS_SCOPE(i_isolate, BigIntObject, BigIntValue);
  return Utils::ToLocal(i::direct_handle(
      i::Cast<i::BigInt>(js_primitive_wrapper->value()), i_isolate));
}

Local<v8::Value> v8::BooleanObject::New(Isolate* v8_isolate, bool value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, BooleanObject, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Object> boolean =
      i::ReadOnlyRoots(i_isolate).boolean_value_handle(value);
  i::Handle<i::Object> obj =
      i::Object::ToObject(i_isolate, boolean).ToHandleChecked();
  return Utils::ToLocal(obj);
}

bool v8::BooleanObject::ValueOf() const {
  i::Tagged<i::Object> obj = *Utils::OpenDirectHandle(this);
  i::Tagged<i::JSPrimitiveWrapper> js_primitive_wrapper =
      i::Cast<i::JSPrimitiveWrapper>(obj);
  i::Isolate* i_isolate = js_primitive_wrapper->GetIsolate();
  API_RCS_SCOPE(i_isolate, BooleanObject, BooleanValue);
  return i::IsTrue(js_primitive_wrapper->value(), i_isolate);
}

Local<v8::Value> v8::StringObject::New(Isolate* v8_isolate,
                                       Local<String> value) {
  auto string = Utils::OpenHandle(*value);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, StringObject, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Object> obj =
      i::Object::ToObject(i_isolate, string).ToHandleChecked();
  return Utils::ToLocal(obj);
}

Local<v8::String> v8::StringObject::ValueOf() const {
  auto obj = Utils::OpenDirectHandle(this);
  auto js_primitive_wrapper = i::Cast<i::JSPrimitiveWrapper>(obj);
  i::Isolate* i_isolate = js_primitive_wrapper->GetIsolate();
  API_RCS_SCOPE(i_isolate, StringObject, StringValue);
  return Utils::ToLocal(i::direct_handle(
      i::Cast<i::String>(js_primitive_wrapper->value()), i_isolate));
}

Local<v8::Value> v8::SymbolObject::New(Isolate* v8_isolate,
                                       Local<Symbol> value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, SymbolObject, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Object> obj =
      i::Object::ToObject(i_isolate, Utils::OpenHandle(*value))
          .ToHandleChecked();
  return Utils::ToLocal(obj);
}

Local<v8::Symbol> v8::SymbolObject::ValueOf() const {
  auto obj = Utils::OpenDirectHandle(this);
  auto js_primitive_wrapper = i::Cast<i::JSPrimitiveWrapper>(obj);
  i::Isolate* i_isolate = js_primitive_wrapper->GetIsolate();
  API_RCS_SCOPE(i_isolate, SymbolObject, SymbolValue);
  return Utils::ToLocal(i::direct_handle(
      i::Cast<i::Symbol>(js_primitive_wrapper->value()), i_isolate));
}

MaybeLocal<v8::Value> v8::Date::New(Local<Context> context, double time) {
  if (std::isnan(time)) {
    // Introduce only canonical NaN value into the VM, to avoid signaling NaNs.
    time = std::numeric_limits<double>::quiet_NaN();
  }
  PREPARE_FOR_EXECUTION(context, Date, New);
  Local<Value> result;
  has_exception =
      !ToLocal<Value>(i::JSDate::New(i_isolate->date_function(),
                                     i_isolate->date_function(), time),
                      &result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(result);
}

MaybeLocal<Value> v8::Date::Parse(Local<Context> context, Local<String> value) {
  PREPARE_FOR_EXECUTION(context, Date, Parse);
  auto string = Utils::OpenHandle(*value);
  double time = ParseDateTimeString(i_isolate, string);

  Local<Value> result;
  has_exception =
      !ToLocal<Value>(i::JSDate::New(i_isolate->date_function(),
                                     i_isolate->date_function(), time),
                      &result);

  RETURN_ON_FAILED_EXECUTION(Value)
  RETURN_ESCAPED(result);
}

double v8::Date::ValueOf() const {
  auto obj = Utils::OpenDirectHandle(this);
  auto jsdate = i::Cast<i::JSDate>(obj);
  return jsdate->value();
}

v8::Local<v8::String> v8::Date::ToISOString() const {
  auto obj = Utils::OpenDirectHandle(this);
  auto jsdate = i::Cast<i::JSDate>(obj);
  i::Isolate* i_isolate = jsdate->GetIsolate();
  i::DateBuffer buffer =
      i::ToDateString(jsdate->value(), i_isolate->date_cache(),
                      i::ToDateStringMode::kISODateAndTime);
  i::Handle<i::String> str = i_isolate->factory()
                                 ->NewStringFromUtf8(base::VectorOf(buffer))
                                 .ToHandleChecked();
  return Utils::ToLocal(str);
}

v8::Local<v8::String> v8::Date::ToUTCString() const {
  auto obj = Utils::OpenDirectHandle(this);
  auto jsdate = i::Cast<i::JSDate>(obj);
  i::Isolate* i_isolate = jsdate->GetIsolate();
  i::DateBuffer buffer =
      i::ToDateString(jsdate->value(), i_isolate->date_cache(),
                      i::ToDateStringMode::kUTCDateAndTime);
  i::Handle<i::String> str = i_isolate->factory()
                                 ->NewStringFromUtf8(base::VectorOf(buffer))
                                 .ToHandleChecked();
  return Utils::ToLocal(str);
}

// Assert that the static TimeZoneDetection cast in
// DateTimeConfigurationChangeNotification is valid.
#define TIME_ZONE_DETECTION_ASSERT_EQ(value)                     \
  static_assert(                                                 \
      static_cast<int>(v8::Isolate::TimeZoneDetection::value) == \
      static_cast<int>(base::TimezoneCache::TimeZoneDetection::value));
TIME_ZONE_DETECTION_ASSERT_EQ(kSkip)
TIME_ZONE_DETECTION_ASSERT_EQ(kRedetect)
#undef TIME_ZONE_DETECTION_ASSERT_EQ

MaybeLocal<v8::RegExp> v8::RegExp::New(Local<Context> context,
                                       Local<String> pattern, Flags flags) {
  PREPARE_FOR_EXECUTION(context, RegExp, New);
  Local<v8::RegExp> result;
  has_exception =
      !ToLocal<RegExp>(i::JSRegExp::New(i_isolate, Utils::OpenHandle(*pattern),
                                        static_cast<i::JSRegExp::Flags>(flags)),
                       &result);
  RETURN_ON_FAILED_EXECUTION(RegExp);
  RETURN_ESCAPED(result);
}

MaybeLocal<v8::RegExp> v8::RegExp::NewWithBacktrackLimit(
    Local<Context> context, Local<String> pattern, Flags flags,
    uint32_t backtrack_limit) {
  Utils::ApiCheck(i::Smi::IsValid(backtrack_limit),
                  "v8::RegExp::NewWithBacktrackLimit",
                  "backtrack_limit is too large or too small");
  Utils::ApiCheck(backtrack_limit != i::JSRegExp::kNoBacktrackLimit,
                  "v8::RegExp::NewWithBacktrackLimit",
                  "Must set backtrack_limit");
  PREPARE_FOR_EXECUTION(context, RegExp, New);
  Local<v8::RegExp> result;
  has_exception = !ToLocal<RegExp>(
      i::JSRegExp::New(i_isolate, Utils::OpenHandle(*pattern),
                       static_cast<i::JSRegExp::Flags>(flags), backtrack_limit),
      &result);
  RETURN_ON_FAILED_EXECUTION(RegExp);
  RETURN_ESCAPED(result);
}

Local<v8::String> v8::RegExp::GetSource() const {
  auto obj = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = obj->GetIsolate();
  return Utils::ToLocal(i::direct_handle(obj->EscapedPattern(), i_isolate));
}

// Assert that the static flags cast in GetFlags is valid.
#define REGEXP_FLAG_ASSERT_EQ(flag)                   \
  static_assert(static_cast<int>(v8::RegExp::flag) == \
                static_cast<int>(i::JSRegExp::flag))
REGEXP_FLAG_ASSERT_EQ(kNone);
REGEXP_FLAG_ASSERT_EQ(kGlobal);
REGEXP_FLAG_ASSERT_EQ(kIgnoreCase);
REGEXP_FLAG_ASSERT_EQ(kMultiline);
REGEXP_FLAG_ASSERT_EQ(kSticky);
REGEXP_FLAG_ASSERT_EQ(kUnicode);
REGEXP_FLAG_ASSERT_EQ(kHasIndices);
REGEXP_FLAG_ASSERT_EQ(kLinear);
REGEXP_FLAG_ASSERT_EQ(kUnicodeSets);
#undef REGEXP_FLAG_ASSERT_EQ

v8::RegExp::Flags v8::RegExp::GetFlags() const {
  auto obj = Utils::OpenDirectHandle(this);
  return RegExp::Flags(static_cast<int>(obj->flags()));
}

MaybeLocal<v8::Object> v8::RegExp::Exec(Local<Context> context,
                                        Local<v8::String> subject) {
  PREPARE_FOR_EXECUTION(context, RegExp, Exec);

  auto regexp = Utils::OpenHandle(this);
  auto subject_string = Utils::OpenHandle(*subject);

  // TODO(jgruber): RegExpUtils::RegExpExec was not written with efficiency in
  // mind. It fetches the 'exec' property and then calls it through JSEntry.
  // Unfortunately, this is currently the only full implementation of
  // RegExp.prototype.exec available in C++.
  Local<v8::Object> result;
  has_exception = !ToLocal<Object>(
      i::RegExpUtils::RegExpExec(i_isolate, regexp, subject_string,
                                 i_isolate->factory()->undefined_value()),
      &result);

  RETURN_ON_FAILED_EXECUTION(Object);
  RETURN_ESCAPED(result);
}

Local<v8::Ar
"""


```