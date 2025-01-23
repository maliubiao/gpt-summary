Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The primary goal is to summarize the functionality of the provided C++ code snippet (`bootstrapper.cc`) from the V8 JavaScript engine. The prompt also requests specific details like its relationship to JavaScript, potential errors, and how it fits within the larger V8 picture. The "part 1 of 11" indicates this is likely part of a broader explanation of V8 initialization.

2. **Initial Scan and Keyword Spotting:** I quickly scan the code for recognizable patterns and keywords. I see:
    * `#include`:  Numerous includes, suggesting dependencies on various V8 components (API, builtins, objects, heap, extensions, etc.). This hints at a central role in the initialization process.
    * `namespace v8::internal`: Confirms this is internal V8 implementation, not external API.
    * `Bootstrapper` class: This is the central entity. The name itself strongly suggests its purpose is related to "booting up" or initializing the JavaScript environment.
    * `Initialize`, `Create`, `Install`: These are common verbs associated with setup and object creation.
    * `Context`, `GlobalObject`, `Function`, `Map`: These are fundamental JavaScript concepts, suggesting the code deals with setting up the basic JavaScript environment.
    * `Extensions`:  The code explicitly mentions handling extensions, which are a way to add custom functionality.
    * `Snapshot`:  Mention of snapshots indicates a mechanism for saving and restoring the engine's state, likely for faster startup.
    * `Builtins`:  References to built-in functions confirm that this code is involved in making core JavaScript functions available.
    * `SourceCodeCache`:  Suggests optimization related to caching source code.

3. **Deduce Core Functionality (High-Level):** Based on the keywords, I can infer that `bootstrapper.cc` is responsible for setting up the initial state of the V8 JavaScript engine. This includes:
    * Creating the core JavaScript objects (like the global object, `Function`, `Object`, etc.).
    * Initializing the execution environment (the `Isolate`).
    * Registering built-in functions and objects.
    * Handling extensions.
    * Potentially using snapshots for faster startup.

4. **Address Specific Questions:** Now, I address the specific points in the request:

    * **File Extension:** The code provided is `.cc`, so it's C++, not Torque.
    * **Relationship to JavaScript:** The entire purpose is to initialize the JavaScript environment. The code creates fundamental JavaScript objects and makes built-in functions available.
    * **JavaScript Examples:** To illustrate the JavaScript connection, I'd provide examples of things the bootstrapper sets up, like creating the global object (`window` or `globalThis`), the `Function` constructor, and the `Object` constructor. I'd also mention how built-in functions like `console.log` become available.
    * **Code Logic/Input/Output:** While the code is complex, I can illustrate a simplified scenario. For example, the `CreateFunction` function takes a name and builtin and produces a JavaScript function object. Input: a string like "console.log", a builtin ID. Output: a JavaScript function object that implements `console.log`.
    * **Common Programming Errors:**  Since this code is internal, the "user" isn't directly interacting with it. However, incorrect extension configuration or attempting to access uninitialized objects *during* the bootstrapping process could be considered internal errors this code helps prevent or manage. I'd frame the examples around incorrect usage *after* the bootstrapping is complete, like assuming a global object exists before initialization is finished (though this is generally handled by the engine).
    * **Summary:**  The summary should reiterate the core function: initializing the V8 JavaScript environment, setting up core objects, builtins, and extensions.

5. **Structure the Answer:** I organize the information logically, starting with the main purpose and then addressing the specific points. I use clear headings and bullet points for readability.

6. **Refine and Elaborate:** I review my initial thoughts and add more detail where necessary. For instance, I elaborate on the role of extensions and snapshots. I also ensure the JavaScript examples are clear and relevant. I make sure to explicitly state it's C++ and not Torque.

7. **Consider the "Part 1 of 11":** This implies a larger process. I would mention that this file is an *early* stage of the initialization and that other parts will likely handle more advanced features and script loading.

By following these steps, I can create a comprehensive and accurate answer that addresses all aspects of the prompt. The key is to break down the complex code into smaller, understandable components and relate them back to the fundamental goal of setting up the JavaScript environment.
好的，让我们来分析一下 `v8/src/init/bootstrapper.cc` 这个 V8 源代码文件的功能。

**功能归纳:**

`v8/src/init/bootstrapper.cc` 的主要功能是 **负责 V8 JavaScript 引擎的启动和初始化过程**。 具体来说，它做了以下关键的事情：

1. **创建和初始化 Isolate:** `Bootstrapper` 类与 `Isolate` 紧密相关，`Isolate` 是 V8 中一个独立的 JavaScript 虚拟机实例。`Bootstrapper` 负责在启动时对 `Isolate` 进行必要的初始化设置。

2. **创建和管理 Native Context:**  它负责创建 `NativeContext`，这是 V8 中运行 JavaScript 代码的核心环境。`NativeContext` 包含了全局对象、内置对象和函数等。

3. **安装内置对象和函数 (Builtins):**  该文件中的代码负责创建和注册 JavaScript 的内置对象和函数，例如 `Object`, `Function`, `Array`, `Math`, `console` 等。这些内置功能是 JavaScript 语言的基础。

4. **处理和加载扩展 (Extensions):**  `Bootstrapper` 负责加载和初始化 V8 的扩展。扩展可以添加额外的功能到 JavaScript 环境中，例如提供 GC 控制、性能分析等。

5. **处理全局代理 (Global Proxy):**  它涉及到 `JSGlobalProxy` 的创建和管理，这是用于隔离不同上下文的机制。

6. **处理快照 (Snapshot):**  `Bootstrapper` 能够处理 V8 的快照机制。快照是 V8 启动时预先创建好的堆状态，可以加速启动过程。它可以从快照恢复环境，也可以创建新的环境。

7. **配置 API 对象模板:** 它允许通过 `ObjectTemplate` 配置全局对象和其他 API 对象的属性和方法。

**关于文件类型和 JavaScript 关系:**

* **文件类型:**  `v8/src/init/bootstrapper.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**。 因此，它不是 Torque 源代码。
* **与 JavaScript 的关系:**  `bootstrapper.cc` 与 JavaScript 的功能有着 **直接且核心** 的关系。它所做的一切都是为了构建和初始化一个能够运行 JavaScript 代码的环境。

**JavaScript 举例说明:**

`bootstrapper.cc` 中创建和初始化的许多对象和函数，我们在 JavaScript 中每天都在使用。以下是一些例子：

```javascript
// 全局对象 (由 Bootstrapper 创建)
console.log("Hello, world!"); // console 对象及其方法

// 内置构造函数 (由 Bootstrapper 创建)
const arr = new Array(1, 2, 3);
const obj = new Object();
const func = new Function('a', 'return a * 2;');

// Math 对象 (由 Bootstrapper 创建)
const randomNum = Math.random();
```

**代码逻辑推理 (假设输入与输出):**

由于代码片段只是头文件的包含和类的声明，没有具体的函数实现，我们无法进行详细的代码逻辑推理。但是，我们可以假设一些场景：

**假设输入:**  在 V8 启动时，`Bootstrapper` 接收到一些配置信息，例如是否使用快照、需要加载哪些扩展等。

**假设输出:**  经过 `Bootstrapper` 的处理，最终会输出一个可以运行 JavaScript 代码的 `Isolate` 实例，其中包含了初始化好的 `NativeContext`、全局对象、内置函数和加载的扩展。

**用户常见的编程错误 (与此文件功能间接相关):**

尽管用户不会直接修改 `bootstrapper.cc`，但 `Bootstrapper` 的工作直接影响着用户编写的 JavaScript 代码的运行。一些常见的编程错误可能与 `Bootstrapper` 初始化的环境有关：

1. **未定义的全局变量/函数:**  如果 `Bootstrapper` 没有正确初始化某些内置对象或函数，用户在 JavaScript 中使用时就会遇到 "undefined" 错误。
   ```javascript
   // 假设 console 对象没有被正确初始化
   console.log("This will cause an error if console is not defined.");
   ```

2. **类型错误:** 如果内置对象的原型链或构造函数没有正确设置，可能会导致类型判断或方法调用出现错误。
   ```javascript
   const arr = [1, 2, 3];
   // 如果 Array 的原型链有问题，以下方法可能无法正常工作
   arr.map(x => x * 2);
   ```

3. **扩展未加载或加载失败:** 如果用户依赖某些 V8 扩展提供的功能，而这些扩展在 `Bootstrapper` 中加载失败，会导致运行时错误。

**总结 (针对第 1 部分):**

`v8/src/init/bootstrapper.cc` 是 V8 引擎启动和初始化的核心组件。它负责创建和配置 JavaScript 运行环境的基础设施，包括 `Isolate`、`NativeContext`、内置对象、函数和扩展。它的正确执行是 JavaScript 代码能够正常运行的先决条件。 虽然用户不会直接与此文件交互，但其功能直接影响着 JavaScript 代码的运行环境和可用功能。

请提供后续的源代码片段，以便进行更深入的分析。

### 提示词
```
这是目录为v8/src/init/bootstrapper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/init/bootstrapper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/init/bootstrapper.h"

#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "src/api/api-natives.h"
#include "src/base/hashmap.h"
#include "src/base/ieee754.h"
#include "src/builtins/accessors.h"
#include "src/codegen/compiler.h"
#include "src/common/globals.h"
#include "src/debug/debug.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/microtask-queue.h"
#include "src/execution/protectors.h"
#include "src/extensions/cputracemark-extension.h"
#include "src/extensions/externalize-string-extension.h"
#include "src/extensions/gc-extension.h"
#include "src/extensions/ignition-statistics-extension.h"
#include "src/extensions/statistics-extension.h"
#include "src/extensions/trigger-failure-extension.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array.h"
#include "src/objects/objects.h"
#include "src/sandbox/testing.h"
#ifdef ENABLE_VTUNE_TRACEMARK
#include "src/extensions/vtunedomain-support-extension.h"
#endif  // ENABLE_VTUNE_TRACEMARK
#include "src/heap/heap-inl.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/numbers/math-random.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/arguments.h"
#include "src/objects/function-kind.h"
#include "src/objects/hash-table-inl.h"
#ifdef V8_INTL_SUPPORT
#include "src/objects/intl-objects.h"
#endif  // V8_INTL_SUPPORT
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-atomics-synchronization.h"
#include "src/objects/js-disposable-stack.h"
#include "src/objects/js-iterator-helpers.h"
#ifdef V8_INTL_SUPPORT
#include "src/objects/js-break-iterator.h"
#include "src/objects/js-collator.h"
#include "src/objects/js-date-time-format.h"
#include "src/objects/js-display-names.h"
#include "src/objects/js-duration-format.h"
#include "src/objects/js-list-format.h"
#include "src/objects/js-locale.h"
#include "src/objects/js-number-format.h"
#include "src/objects/js-plural-rules.h"
#endif  // V8_INTL_SUPPORT
#include "src/objects/js-regexp-string-iterator.h"
#include "src/objects/js-regexp.h"
#include "src/objects/js-shadow-realm.h"
#ifdef V8_INTL_SUPPORT
#include "src/objects/js-relative-time-format.h"
#include "src/objects/js-segment-iterator.h"
#include "src/objects/js-segmenter.h"
#include "src/objects/js-segments.h"
#endif  // V8_INTL_SUPPORT
#include "src/codegen/script-details.h"
#include "src/objects/js-raw-json.h"
#include "src/objects/js-shared-array.h"
#include "src/objects/js-struct.h"
#include "src/objects/js-temporal-objects-inl.h"
#include "src/objects/js-weak-refs.h"
#include "src/objects/ordered-hash-table.h"
#include "src/objects/property-cell.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/slots-inl.h"
#include "src/objects/swiss-name-dictionary-inl.h"
#include "src/objects/templates.h"
#include "src/snapshot/snapshot.h"
#include "src/zone/zone-hashmap.h"

#ifdef V8_FUZZILLI
#include "src/fuzzilli/fuzzilli.h"
#endif

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-js.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

void SourceCodeCache::Initialize(Isolate* isolate, bool create_heap_objects) {
  cache_ = create_heap_objects ? ReadOnlyRoots(isolate).empty_fixed_array()
                               : Tagged<FixedArray>();
}

void SourceCodeCache::Iterate(RootVisitor* v) {
  v->VisitRootPointer(Root::kExtensions, nullptr, FullObjectSlot(&cache_));
}

bool SourceCodeCache::Lookup(Isolate* isolate, base::Vector<const char> name,
                             DirectHandle<SharedFunctionInfo>* handle) {
  for (int i = 0; i < cache_->length(); i += 2) {
    Tagged<SeqOneByteString> str = Cast<SeqOneByteString>(cache_->get(i));
    if (str->IsOneByteEqualTo(name)) {
      *handle =
          direct_handle(Cast<SharedFunctionInfo>(cache_->get(i + 1)), isolate);
      return true;
    }
  }
  return false;
}

void SourceCodeCache::Add(Isolate* isolate, base::Vector<const char> name,
                          DirectHandle<SharedFunctionInfo> shared) {
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  int length = cache_->length();
  DirectHandle<FixedArray> new_array =
      factory->NewFixedArray(length + 2, AllocationType::kOld);
  FixedArray::CopyElements(isolate, *new_array, 0, cache_, 0, cache_->length());
  cache_ = *new_array;
  Handle<String> str =
      factory
          ->NewStringFromOneByte(base::Vector<const uint8_t>::cast(name),
                                 AllocationType::kOld)
          .ToHandleChecked();
  DCHECK(!str.is_null());
  cache_->set(length, *str);
  cache_->set(length + 1, *shared);
  Cast<Script>(shared->script())->set_type(type_);
}

Bootstrapper::Bootstrapper(Isolate* isolate)
    : isolate_(isolate),
      nesting_(0),
      extensions_cache_(Script::Type::kExtension) {}

void Bootstrapper::Initialize(bool create_heap_objects) {
  extensions_cache_.Initialize(isolate_, create_heap_objects);
}

static const char* GCFunctionName() {
  bool flag_given =
      v8_flags.expose_gc_as != nullptr && strlen(v8_flags.expose_gc_as) != 0;
  return flag_given ? v8_flags.expose_gc_as : "gc";
}

static bool isValidCpuTraceMarkFunctionName() {
  return v8_flags.expose_cputracemark_as != nullptr &&
         strlen(v8_flags.expose_cputracemark_as) != 0;
}

void Bootstrapper::InitializeOncePerProcess() {
  v8::RegisterExtension(std::make_unique<GCExtension>(GCFunctionName()));
#ifdef V8_FUZZILLI
  v8::RegisterExtension(std::make_unique<FuzzilliExtension>("fuzzilli"));
#endif
  v8::RegisterExtension(std::make_unique<ExternalizeStringExtension>());
  v8::RegisterExtension(std::make_unique<StatisticsExtension>());
  v8::RegisterExtension(std::make_unique<TriggerFailureExtension>());
  v8::RegisterExtension(std::make_unique<IgnitionStatisticsExtension>());
  if (isValidCpuTraceMarkFunctionName()) {
    v8::RegisterExtension(std::make_unique<CpuTraceMarkExtension>(
        v8_flags.expose_cputracemark_as));
  }
#ifdef ENABLE_VTUNE_TRACEMARK
  v8::RegisterExtension(
      std::make_unique<VTuneDomainSupportExtension>("vtunedomainmark"));
#endif  // ENABLE_VTUNE_TRACEMARK
}

void Bootstrapper::TearDown() {
  extensions_cache_.Initialize(isolate_, false);  // Yes, symmetrical
}

class Genesis {
 public:
  Genesis(Isolate* isolate, MaybeHandle<JSGlobalProxy> maybe_global_proxy,
          v8::Local<v8::ObjectTemplate> global_proxy_template,
          size_t context_snapshot_index,
          DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
          v8::MicrotaskQueue* microtask_queue);
  Genesis(Isolate* isolate, MaybeHandle<JSGlobalProxy> maybe_global_proxy,
          v8::Local<v8::ObjectTemplate> global_proxy_template);
  ~Genesis() = default;

  Isolate* isolate() const { return isolate_; }
  Factory* factory() const { return isolate_->factory(); }
  Builtins* builtins() const { return isolate_->builtins(); }
  Heap* heap() const { return isolate_->heap(); }

  DirectHandle<NativeContext> result() { return result_; }

  DirectHandle<JSGlobalProxy> global_proxy() { return global_proxy_; }

 private:
  DirectHandle<NativeContext> native_context() { return native_context_; }

  // Creates some basic objects. Used for creating a context from scratch.
  void CreateRoots();
  // Creates the empty function.  Used for creating a context from scratch.
  Handle<JSFunction> CreateEmptyFunction();
  // Returns the %ThrowTypeError% intrinsic function.
  // See ES#sec-%throwtypeerror% for details.
  DirectHandle<JSFunction> GetThrowTypeErrorIntrinsic();

  void CreateSloppyModeFunctionMaps(Handle<JSFunction> empty);
  void CreateStrictModeFunctionMaps(Handle<JSFunction> empty);
  void CreateObjectFunction(DirectHandle<JSFunction> empty);
  void CreateIteratorMaps(Handle<JSFunction> empty);
  void CreateAsyncIteratorMaps(Handle<JSFunction> empty);
  void CreateAsyncFunctionMaps(Handle<JSFunction> empty);
  void CreateJSProxyMaps();

  // Make the "arguments" and "caller" properties throw a TypeError on access.
  void AddRestrictedFunctionProperties(DirectHandle<JSFunction> empty);

  // Creates the global objects using the global proxy and the template passed
  // in through the API.  We call this regardless of whether we are building a
  // context from scratch or using a deserialized one from the context snapshot
  // but in the latter case we don't use the objects it produces directly, as
  // we have to use the deserialized ones that are linked together with the
  // rest of the context snapshot. At the end we link the global proxy and the
  // context to each other.
  Handle<JSGlobalObject> CreateNewGlobals(
      v8::Local<v8::ObjectTemplate> global_proxy_template,
      DirectHandle<JSGlobalProxy> global_proxy);
  // Similarly, we want to use the global that has been created by the templates
  // passed through the API.  The global from the snapshot is detached from the
  // other objects in the snapshot.
  void HookUpGlobalObject(Handle<JSGlobalObject> global_object);
  // Hooks the given global proxy into the context in the case we do not
  // replace the global object from the deserialized native context.
  void HookUpGlobalProxy(DirectHandle<JSGlobalProxy> global_proxy);
  // The native context has a ScriptContextTable that store declarative bindings
  // made in script scopes.  Add a "this" binding to that table pointing to the
  // global proxy.
  void InstallGlobalThisBinding();
  // New context initialization.  Used for creating a context from scratch.
  void InitializeGlobal(Handle<JSGlobalObject> global_object,
                        Handle<JSFunction> empty_function);
  void InitializeExperimentalGlobal();
  void InitializeIteratorFunctions();
  void InitializeCallSiteBuiltins();
  void InitializeConsole(Handle<JSObject> extras_binding);

#define DECLARE_FEATURE_INITIALIZATION(id, descr) void InitializeGlobal_##id();

  HARMONY_INPROGRESS(DECLARE_FEATURE_INITIALIZATION)
  JAVASCRIPT_INPROGRESS_FEATURES(DECLARE_FEATURE_INITIALIZATION)
  HARMONY_STAGED(DECLARE_FEATURE_INITIALIZATION)
  JAVASCRIPT_STAGED_FEATURES(DECLARE_FEATURE_INITIALIZATION)
  HARMONY_SHIPPING(DECLARE_FEATURE_INITIALIZATION)
  JAVASCRIPT_SHIPPING_FEATURES(DECLARE_FEATURE_INITIALIZATION)
#undef DECLARE_FEATURE_INITIALIZATION
  void InitializeGlobal_regexp_linear_flag();
  void InitializeGlobal_sharedarraybuffer();
#if V8_ENABLE_WEBASSEMBLY
  void InitializeWasmJSPI();
#endif

  enum ArrayBufferKind { ARRAY_BUFFER, SHARED_ARRAY_BUFFER };
  Handle<JSFunction> CreateArrayBuffer(Handle<String> name,
                                       ArrayBufferKind array_buffer_kind);

  bool InstallABunchOfRandomThings();
  bool InstallExtrasBindings();

  Handle<JSFunction> InstallTypedArray(const char* name,
                                       ElementsKind elements_kind,
                                       InstanceType constructor_type,
                                       int rab_gsab_initial_map_index);
  void InitializeMapCaches();

  enum ExtensionTraversalState { UNVISITED, VISITED, INSTALLED };

  class ExtensionStates {
   public:
    ExtensionStates();
    ExtensionStates(const ExtensionStates&) = delete;
    ExtensionStates& operator=(const ExtensionStates&) = delete;
    ExtensionTraversalState get_state(RegisteredExtension* extension);
    void set_state(RegisteredExtension* extension,
                   ExtensionTraversalState state);

   private:
    base::HashMap map_;
  };

  // Used both for deserialized and from-scratch contexts to add the extensions
  // provided.
  static bool InstallExtensions(Isolate* isolate,
                                DirectHandle<Context> native_context,
                                v8::ExtensionConfiguration* extensions);
  static bool InstallAutoExtensions(Isolate* isolate,
                                    ExtensionStates* extension_states);
  static bool InstallRequestedExtensions(Isolate* isolate,
                                         v8::ExtensionConfiguration* extensions,
                                         ExtensionStates* extension_states);
  static bool InstallExtension(Isolate* isolate, const char* name,
                               ExtensionStates* extension_states);
  static bool InstallExtension(Isolate* isolate,
                               v8::RegisteredExtension* current,
                               ExtensionStates* extension_states);
  static bool InstallSpecialObjects(Isolate* isolate,
                                    DirectHandle<NativeContext> native_context);
  bool ConfigureApiObject(Handle<JSObject> object,
                          Handle<ObjectTemplateInfo> object_template);
  bool ConfigureGlobalObject(
      v8::Local<v8::ObjectTemplate> global_proxy_template);

  // Migrates all properties from the 'from' object to the 'to'
  // object and overrides the prototype in 'to' with the one from
  // 'from'.
  void TransferObject(DirectHandle<JSObject> from, Handle<JSObject> to);
  void TransferNamedProperties(DirectHandle<JSObject> from,
                               Handle<JSObject> to);
  void TransferIndexedProperties(DirectHandle<JSObject> from,
                                 DirectHandle<JSObject> to);

  Handle<Map> CreateInitialMapForArraySubclass(int size,
                                               int inobject_properties);

  static bool CompileExtension(Isolate* isolate, v8::Extension* extension);

  Isolate* isolate_;
  DirectHandle<NativeContext> result_;
  DirectHandle<NativeContext> native_context_;
  DirectHandle<JSGlobalProxy> global_proxy_;

  // %ThrowTypeError%. See ES#sec-%throwtypeerror% for details.
  DirectHandle<JSFunction> restricted_properties_thrower_;

  BootstrapperActive active_;
  friend class Bootstrapper;
};

void Bootstrapper::Iterate(RootVisitor* v) {
  extensions_cache_.Iterate(v);
  v->Synchronize(VisitorSynchronization::kExtensions);
}

DirectHandle<NativeContext> Bootstrapper::CreateEnvironment(
    MaybeHandle<JSGlobalProxy> maybe_global_proxy,
    v8::Local<v8::ObjectTemplate> global_proxy_template,
    v8::ExtensionConfiguration* extensions, size_t context_snapshot_index,
    DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
    v8::MicrotaskQueue* microtask_queue) {
  HandleScope scope(isolate_);
  DirectHandle<NativeContext> env;
  {
    Genesis genesis(isolate_, maybe_global_proxy, global_proxy_template,
                    context_snapshot_index, embedder_fields_deserializer,
                    microtask_queue);
    env = genesis.result();
    if (env.is_null() || !InstallExtensions(env, extensions)) {
      return {};
    }
  }
  LogAllMaps();
  isolate_->heap()->NotifyBootstrapComplete();
  return scope.CloseAndEscape(env);
}

DirectHandle<JSGlobalProxy> Bootstrapper::NewRemoteContext(
    MaybeHandle<JSGlobalProxy> maybe_global_proxy,
    v8::Local<v8::ObjectTemplate> global_proxy_template) {
  HandleScope scope(isolate_);
  DirectHandle<JSGlobalProxy> global_proxy;
  {
    Genesis genesis(isolate_, maybe_global_proxy, global_proxy_template);
    global_proxy = genesis.global_proxy();
    if (global_proxy.is_null()) return Handle<JSGlobalProxy>();
  }
  LogAllMaps();
  return scope.CloseAndEscape(global_proxy);
}

void Bootstrapper::LogAllMaps() {
  if (!v8_flags.log_maps || isolate_->initialized_from_snapshot()) return;
  // Log all created Map objects that are on the heap. For snapshots the Map
  // logging happens during deserialization in order to avoid printing Maps
  // multiple times during partial deserialization.
  LOG(isolate_, LogAllMaps());
}

namespace {

#ifdef DEBUG
bool IsFunctionMapOrSpecialBuiltin(DirectHandle<Map> map, Builtin builtin,
                                   DirectHandle<Context> context) {
  // During bootstrapping some of these maps could be not created yet.
  return ((*map == context->get(Context::STRICT_FUNCTION_MAP_INDEX)) ||
          (*map == context->get(
                       Context::STRICT_FUNCTION_WITHOUT_PROTOTYPE_MAP_INDEX)) ||
          (*map ==
           context->get(
               Context::STRICT_FUNCTION_WITH_READONLY_PROTOTYPE_MAP_INDEX)) ||
          // Check if it's a creation of an empty or Proxy function during
          // bootstrapping.
          (builtin == Builtin::kEmptyFunction ||
           builtin == Builtin::kProxyConstructor));
}
#endif  // DEBUG

Handle<SharedFunctionInfo> CreateSharedFunctionInfoForBuiltin(
    Isolate* isolate, Handle<String> name, Builtin builtin, int len,
    AdaptArguments adapt) {
  Handle<SharedFunctionInfo> info =
      isolate->factory()->NewSharedFunctionInfoForBuiltin(name, builtin, len,
                                                          adapt);
  info->set_language_mode(LanguageMode::kStrict);

#ifdef DEBUG
  Tagged<Code> code = info->GetCode(isolate);
  if (code->parameter_count() != kDontAdaptArgumentsSentinel) {
    DCHECK_EQ(info->internal_formal_parameter_count_with_receiver(),
              code->parameter_count());
  }
#endif

  return info;
}

V8_NOINLINE Handle<JSFunction> CreateFunctionForBuiltin(
    Isolate* isolate, Handle<String> name, Handle<Map> map, Builtin builtin,
    int len, AdaptArguments adapt) {
  Handle<NativeContext> context(isolate->native_context());
  DCHECK(IsFunctionMapOrSpecialBuiltin(map, builtin, context));

  Handle<SharedFunctionInfo> info =
      CreateSharedFunctionInfoForBuiltin(isolate, name, builtin, len, adapt);

  return Factory::JSFunctionBuilder{isolate, info, context}
      .set_map(map)
      .Build();
}

V8_NOINLINE Handle<JSFunction> CreateFunctionForBuiltinWithPrototype(
    Isolate* isolate, Handle<String> name, Builtin builtin,
    Handle<UnionOf<JSPrototype, Hole>> prototype, InstanceType type,
    int instance_size, int inobject_properties,
    MutableMode prototype_mutability, int len, AdaptArguments adapt) {
  Factory* factory = isolate->factory();
  Handle<NativeContext> context(isolate->native_context());
  Handle<Map> map =
      prototype_mutability == MUTABLE
          ? isolate->strict_function_map()
          : isolate->strict_function_with_readonly_prototype_map();
  DCHECK(IsFunctionMapOrSpecialBuiltin(map, builtin, context));

  Handle<SharedFunctionInfo> info =
      CreateSharedFunctionInfoForBuiltin(isolate, name, builtin, len, adapt);
  info->set_expected_nof_properties(inobject_properties);

  Handle<JSFunction> result =
      Factory::JSFunctionBuilder{isolate, info, context}.set_map(map).Build();

  ElementsKind elements_kind;
  switch (type) {
    case JS_ARRAY_TYPE:
      elements_kind = PACKED_SMI_ELEMENTS;
      break;
    case JS_ARGUMENTS_OBJECT_TYPE:
      elements_kind = PACKED_ELEMENTS;
      break;
    default:
      elements_kind = TERMINAL_FAST_ELEMENTS_KIND;
      break;
  }
  Handle<Map> initial_map = factory->NewContextfulMapForCurrentContext(
      type, instance_size, elements_kind, inobject_properties);
  initial_map->SetConstructor(*result);
  if (type == JS_FUNCTION_TYPE) {
    DCHECK_EQ(instance_size, JSFunction::kSizeWithPrototype);
    // Since we are creating an initial map for JSFunction objects with
    // prototype slot, set the respective bit.
    initial_map->set_has_prototype_slot(true);
  }
  // TODO(littledan): Why do we have this is_generator test when
  // NewFunctionPrototype already handles finding an appropriately
  // shared prototype?
  if (!IsResumableFunction(info->kind()) && IsTheHole(*prototype, isolate)) {
    prototype = factory->NewFunctionPrototype(result);
  }
  JSFunction::SetInitialMap(isolate, result, initial_map,
                            Cast<JSPrototype>(prototype));

  return result;
}

V8_NOINLINE Handle<JSFunction> CreateFunctionForBuiltinWithoutPrototype(
    Isolate* isolate, Handle<String> name, Builtin builtin, int len,
    AdaptArguments adapt) {
  Handle<NativeContext> context(isolate->native_context());
  Handle<Map> map = isolate->strict_function_without_prototype_map();
  DCHECK(IsFunctionMapOrSpecialBuiltin(map, builtin, context));

  Handle<SharedFunctionInfo> info =
      CreateSharedFunctionInfoForBuiltin(isolate, name, builtin, len, adapt);

  return Factory::JSFunctionBuilder{isolate, info, context}
      .set_map(map)
      .Build();
}

V8_NOINLINE Handle<JSFunction> CreateFunction(
    Isolate* isolate, Handle<String> name, InstanceType type, int instance_size,
    int inobject_properties, Handle<UnionOf<JSPrototype, Hole>> prototype,
    Builtin builtin, int len, AdaptArguments adapt) {
  DCHECK(Builtins::HasJSLinkage(builtin));

  Handle<JSFunction> result = CreateFunctionForBuiltinWithPrototype(
      isolate, name, builtin, prototype, type, instance_size,
      inobject_properties, IMMUTABLE, len, adapt);

  // Make the JSFunction's prototype object fast.
  JSObject::MakePrototypesFast(handle(result->prototype(), isolate),
                               kStartAtReceiver, isolate);

  // Make the resulting JSFunction object fast.
  JSObject::MakePrototypesFast(result, kStartAtReceiver, isolate);
  result->shared()->set_native(true);
  return result;
}

V8_NOINLINE Handle<JSFunction> CreateFunction(
    Isolate* isolate, const char* name, InstanceType type, int instance_size,
    int inobject_properties, Handle<UnionOf<JSPrototype, Hole>> prototype,
    Builtin builtin, int len, AdaptArguments adapt) {
  return CreateFunction(
      isolate, isolate->factory()->InternalizeUtf8String(name), type,
      instance_size, inobject_properties, prototype, builtin, len, adapt);
}

V8_NOINLINE Handle<JSFunction> InstallFunction(
    Isolate* isolate, Handle<JSObject> target, Handle<String> name,
    InstanceType type, int instance_size, int inobject_properties,
    Handle<UnionOf<JSPrototype, Hole>> prototype, Builtin call, int len,
    AdaptArguments adapt) {
  DCHECK(Builtins::HasJSLinkage(call));
  Handle<JSFunction> function =
      CreateFunction(isolate, name, type, instance_size, inobject_properties,
                     prototype, call, len, adapt);
  JSObject::AddProperty(isolate, target, name, function, DONT_ENUM);
  return function;
}

V8_NOINLINE Handle<JSFunction> InstallFunction(
    Isolate* isolate, Handle<JSObject> target, const char* name,
    InstanceType type, int instance_size, int inobject_properties,
    Handle<UnionOf<JSPrototype, Hole>> prototype, Builtin call, int len,
    AdaptArguments adapt) {
  return InstallFunction(
      isolate, target, isolate->factory()->InternalizeUtf8String(name), type,
      instance_size, inobject_properties, prototype, call, len, adapt);
}

// This sets a constructor instance type on the constructor map which will be
// used in IsXxxConstructor() predicates. Having such predicates helps figuring
// out if a protector cell should be invalidated. If there are no protector
// cell checks required for constructor, this function must not be used.
// Note, this function doesn't create a copy of the constructor's map. So it's
// better to set constructor instance type after all the properties are added
// to the constructor and thus the map is already guaranteed to be unique.
V8_NOINLINE void SetConstructorInstanceType(
    Isolate* isolate, DirectHandle<JSFunction> constructor,
    InstanceType constructor_type) {
  DCHECK(InstanceTypeChecker::IsJSFunction(constructor_type));
  DCHECK_NE(constructor_type, JS_FUNCTION_TYPE);

  Tagged<Map> map = constructor->map();

  // Check we don't accidentally change one of the existing maps.
  DCHECK_NE(map, *isolate->strict_function_map());
  DCHECK_NE(map, *isolate->strict_function_with_readonly_prototype_map());
  // Constructor function map is always a root map, and thus we don't have to
  // deal with updating the whole transition tree.
  DCHECK(IsUndefined(map->GetBackPointer(), isolate));
  DCHECK_EQ(JS_FUNCTION_TYPE, map->instance_type());

  map->set_instance_type(constructor_type);
}

V8_NOINLINE Handle<JSFunction> SimpleCreateFunction(Isolate* isolate,
                                                    Handle<String> name,
                                                    Builtin call, int len,
                                                    AdaptArguments adapt) {
  DCHECK(Builtins::HasJSLinkage(call));
  name = String::Flatten(isolate, name, AllocationType::kOld);
  Handle<JSFunction> fun =
      CreateFunctionForBuiltinWithoutPrototype(isolate, name, call, len, adapt);
  // Make the resulting JSFunction object fast.
  JSObject::MakePrototypesFast(fun, kStartAtReceiver, isolate);
  fun->shared()->set_native(true);
  return fun;
}

V8_NOINLINE Handle<JSFunction> InstallFunctionWithBuiltinId(
    Isolate* isolate, Handle<JSObject> base, const char* name, Builtin call,
    int len, AdaptArguments adapt) {
  Handle<String> internalized_name =
      isolate->factory()->InternalizeUtf8String(name);
  Handle<JSFunction> fun =
      SimpleCreateFunction(isolate, internalized_name, call, len, adapt);
  JSObject::AddProperty(isolate, base, internalized_name, fun, DONT_ENUM);
  return fun;
}

V8_NOINLINE Handle<JSFunction> InstallFunctionAtSymbol(
    Isolate* isolate, Handle<JSObject> base, Handle<Symbol> symbol,
    const char* symbol_string, Builtin call, int len, AdaptArguments adapt,
    PropertyAttributes attrs = DONT_ENUM) {
  Handle<String> internalized_symbol =
      isolate->factory()->InternalizeUtf8String(symbol_string);
  Handle<JSFunction> fun =
      SimpleCreateFunction(isolate, internalized_symbol, call, len, adapt);
  JSObject::AddProperty(isolate, base, symbol, fun, attrs);
  return fun;
}

V8_NOINLINE Handle<JSFunction> CreateSharedObjectConstructor(
    Isolate* isolate, Handle<String> name, DirectHandle<Map> instance_map,
    Builtin builtin, int len, AdaptArguments adapt) {
  Factory* factory = isolate->factory();
  Handle<SharedFunctionInfo> info =
      factory->NewSharedFunctionInfoForBuiltin(name, builtin, len, adapt);
  info->set_language_mode(LanguageMode::kStrict);
  Handle<JSFunction> constructor =
      Factory::JSFunctionBuilder{isolate, info, isolate->native_context()}
          .set_map(isolate->strict_function_with_readonly_prototype_map())
          .Build();
  constructor->set_prototype_or_initial_map(*instance_map, kReleaseStore);

  JSObject::AddProperty(
      isolate, constructor, factory->has_instance_symbol(),
      handle(isolate->native_context()->shared_space_js_object_has_instance(),
             isolate),
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY));
  return constructor;
}

V8_NOINLINE void SimpleInstallGetterSetter(Isolate* isolate,
                                           Handle<JSObject> base,
                                           Handle<Name> name,
                                           Builtin call_getter,
                                           Builtin call_setter) {
  Handle<String> getter_name =
      Name::ToFunctionName(isolate, name, isolate->factory()->get_string())
          .ToHandleChecked();
  DirectHandle<JSFunction> getter =
      SimpleCreateFunction(isolate, getter_name, call_getter, 0, kAdapt);

  Handle<String> setter_name =
      Name::ToFunctionName(isolate, name, isolate->factory()->set_string())
          .ToHandleChecked();
  DirectHandle<JSFunction> setter =
      SimpleCreateFunction(isolate, setter_name, call_setter, 1, kAdapt);

  JSObject::DefineOwnAccessorIgnoreAttributes(base, name, getter, setter,
                                              DONT_ENUM)
      .Check();
}

void SimpleInstallGetterSetter(Isolate* isolate, Handle<JSObject> base,
                               const char* name, Builtin call_getter,
                               Builtin call_setter) {
  SimpleInstallGetterSetter(isolate, base,
                            isolate->factory()->InternalizeUtf8String(name),
                            call_getter, call_setter);
}

V8_NOINLINE Handle<JSFunction> SimpleInstallGetter(
    Isolate* isolate, Handle<JSObject> base, Handle<Name> name,
    Handle<Name> property_name, Builtin call, AdaptArguments adapt) {
  Handle<String> getter_name =
      Name::ToFunctionName(isolate, name, isolate->factory()->get_string())
          .ToHandleChecked();
  Handle<JSFunction> getter =
      SimpleCreateFunction(isolate, getter_name, call, 0, adapt);

  DirectHandle<Object> setter = isolate->factory()->undefined_value();

  JSObject::DefineOwnAccessorIgnoreAttributes(base, property_name, getter,
                                              setter, DONT_ENUM)
      .Check();

  return getter;
}

V8_NOINLINE Handle<JSFunction> SimpleInstallGetter(Isolate* isolate,
                                                   Handle<JSObject> base,
                                                   Handle<Name> name,
                                                   Builtin call,
                                                   AdaptArguments adapt) {
  return SimpleInstallGetter(isolate, base, name, name, call, adapt);
}

V8_NOINLINE void InstallConstant(Isolate* isolate, Handle<JSObject> holder,
                                 const char* name, DirectHandle<Object> value) {
  JSObject::AddProperty(
      isolate, holder, isolate->factory()->InternalizeUtf8String(name), value,
      static_cast<PropertyAttributes>(DONT_DELETE | DONT_ENUM | READ_ONLY));
}

V8_NOINLINE void InstallTrueValuedProperty(Isolate* isolate,
                                           Handle<JSObject> holder,
                                           const char* name) {
  JSObject::AddProperty(isolate, holder,
                        isolate->factory()->InternalizeUtf8String(name),
                        isolate->factory()->true_value(), NONE);
}

V8_NOINLINE void InstallSpeciesGetter(Isolate* isolate,
                                      Handle<JSFunction> constructor) {
  Factory* factory = isolate->factory();
  // TODO(adamk): We should be able to share a SharedFunctionInfo
  // between all these JSFunctins.
  SimpleInstallGetter(isolate, constructor, factory->symbol_species_string(),
                      factory->species_symbol(), Builtin::kReturnReceiver,
                      kAdapt);
}

V8_NOINLINE void InstallToStringTag(Isolate* isolate, Handle<JSObject> holder,
                                    DirectHandle<String> value) {
  JSObject::AddProperty(isolate, holder,
                        isolate->factory()->to_string_tag_symbol(), value,
                        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));
}

void InstallToStringTag(Isolate* isolate, Handle<JSObject> holder,
                        const char* value) {
  InstallToStringTag(isolate, holder,
                     isolate->factory()->InternalizeUtf8String(value));
}

// Create a map for result objects returned from builtins in such a way that
// it's exactly the same map as the one produced by object literals. E.g.,
// iterator result objects have the same map as literals in the form `{value,
// done}`.
//
// This way we have better sharing of maps (i.e. less polymorphism) and also
// make it possible to hit the fast-paths in various builtins (i.e. promises and
// collections) with user defined iterators.
template <size_t N>
Handle<Map> CreateLiteralObjectMapFromCache(
    Isolate* isolate, const std::array<Handle<Name>, N>& properties) {
  Factory* factory = isolate->factory();
  DirectHandle<NativeContext> native_context = isolate->native_context();
  Handle<Map> map = factory->ObjectLiteralMapFromCache(native_context, N);
  for (Handle<Name> name : properties) {
    map = Map::CopyWithField(isolate, map, name, FieldType::Any(isolate), NONE,
                             PropertyConstness::kConst,
                             Representation::Tagged(), INSERT_TRANSITION)
              .ToHandleChecked();
  }
  return map;
}

}  // namespace

Handle<JSFunction> Genesis::CreateEmptyFunction() {
  // Allocate the function map first and then patch the prototype later.
  Handle<Map> empty_function_map = factory()->CreateSloppyFunctionMap(
      FUNCTION_WITHOUT_PROTOTYPE, MaybeHandle<JSFunction>());
  empty_function_map->set_is_prototype_map(true);
  DCHECK(!empty_function_map->is_dictionary_map());

  // Allocate the empty function as the prototype for function according to
  // ES#sec-properties-of-the-function-prototype-object
  Handle<JSFunction> empty_function = CreateFunctionForBuiltin(
      isolate(), factory()->empty_string(), empty_function_map,
      Builtin::kEmptyFunction, 0, kDontAdapt);
  empty_function_map->SetConstructor(*empty_function);
  native_context()->set_empty_function(*empty_function);

  // --- E m p t y ---
  DirectHandle<String> source = factory()->InternalizeSt
```