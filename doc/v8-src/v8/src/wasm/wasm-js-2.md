Response: The user wants a summary of the C++ code provided, focusing on its functionality and relationship with JavaScript. Since this is part 3 of 3, the summary should encompass the complete functionality described across all three parts.

Here's a breakdown of the code's function:

1. **Initialization of WebAssembly JavaScript API:** This code is responsible for setting up the `WebAssembly` global object in JavaScript and its associated constructors and prototypes. This involves creating classes like `WebAssembly.Module`, `WebAssembly.Memory`, `WebAssembly.Table`, `WebAssembly.Global`, `WebAssembly.Tag`, and `WebAssembly.Exception`.

2. **Installation of Constructors and Prototypes:**  The code uses helper functions like `InstallConstructorFunc` and `SetupConstructor` to create the constructor functions for the WebAssembly API objects and to define their prototypes. These prototypes contain methods like `grow`, `set`, `get`, `valueOf`, etc.

3. **Linking C++ functions to JavaScript methods:** Functions like `wasm::WebAssemblyTableGetLength`, `wasm::WebAssemblyMemoryGrow`, etc., which are implemented in C++, are exposed as methods on the JavaScript WebAssembly objects' prototypes. This allows JavaScript code to interact with the underlying WebAssembly functionality.

4. **Handling Errors:** The code sets up constructors for `WebAssembly.CompileError`, `WebAssembly.LinkError`, and `WebAssembly.RuntimeError`, making these error types available in JavaScript.

5. **Supporting Asynchronous Compilation (Streaming):** The code includes logic for handling asynchronous compilation of WebAssembly modules using `compileStreaming` and `instantiateStreaming`. This allows modules to be compiled while being downloaded.

6. **Implementing Optional Features:**  The code checks for and installs optional WebAssembly features like type reflection and the JavaScript Promise Integration (JSPI).

7. **Type Reflection:** The type reflection feature exposes the types of WebAssembly objects (like tables, memories, globals, and functions) to JavaScript via a `type` method.

8. **JavaScript Promise Integration (JSPI):** This feature enables better integration between WebAssembly and JavaScript Promises, allowing for asynchronous operations and stack switching. It introduces `WebAssembly.Suspending` and `WebAssembly.promising`.

9. **Conditional Installation:**  Features like JSPI are installed conditionally based on flags or requests.

To illustrate the connection with JavaScript, I'll use examples showing how these C++ functions and structures become accessible and usable in JavaScript.
这个C++源代码文件（`v8/src/wasm/wasm-js.cc` 的第三部分）的主要功能是**完成WebAssembly JavaScript API的初始化和安装，并根据配置启用可选的WebAssembly功能。**

这是对前面两部分工作的补充，它确保了WebAssembly的核心API在JavaScript环境中可用，并根据需要添加了额外的特性。

具体来说，这部分代码做了以下事情：

1. **安装 `WebAssembly.Module` 构造函数及其方法:**
   - 创建 `WebAssembly.Module` 构造函数，用于创建 WebAssembly 模块对象。
   - 安装 `imports`、`exports` 和 `customSections` 等静态方法到 `WebAssembly.Module` 构造函数上，这些方法允许 JavaScript 代码检查模块的导入、导出和自定义段。

2. **安装完整的 WebAssembly API 到全局对象:**
   - 检查 WebAssembly API 是否已经安装。
   - 将之前创建的各种 WebAssembly 构造函数 (如 `Memory`, `Table`, `Global`, `Tag`, `Exception`) 和 `WebAssembly` 对象本身添加到全局 JavaScript 对象中，使其在 JavaScript 代码中可以访问。
   - 只有在非 `jitless` 模式下（或满足特定条件，如测试或启用了 `wasm_jitless`），才会将 `WebAssembly` 对象暴露到全局作用域。

3. **处理 WebAssembly 标签 (Tag) 的类型索引:**
   - 基于当前的 `Isolate` (V8 的隔离环境) 的类型规范化器，重置 `WebAssembly.Tag` 的规范类型索引。

4. **处理 WebAssembly 的流式编译和实例化 (Streaming):**
   - 如果启用了 `wasm_test_streaming` 标志，则设置一个用于测试的流式回调函数。
   - 如果设置了流式回调函数 (通常用于异步编译)，则安装 `compileStreaming` 和 `instantiateStreaming` 方法到 `WebAssembly` 对象上。

5. **安装可选的 WebAssembly 功能:**
   - **类型反射 (Type Reflection):** 如果启用了类型反射功能，则安装 `WebAssembly.Function` 构造函数，并为 `WebAssembly.Table.prototype`、`WebAssembly.Memory.prototype`、`WebAssembly.Global.prototype` 和 `WebAssembly.Tag.prototype` 添加 `type` 属性，允许 JavaScript 代码获取这些 WebAssembly 对象的类型信息。
   - **JavaScript Promise 集成 (JSPI):** 如果启用了 JSPI 功能，则初始化 JSPI 相关的数据结构，并安装 `WebAssembly.Suspending` 构造函数和 `WebAssembly.promising` 方法，以便更好地与 JavaScript Promise 集成，支持异步操作。

6. **条件化安装功能:**
   - 提供了 `InstallConditionalFeatures` 函数，允许根据运行时的条件（例如，是否请求了 JSPI）来动态安装某些可选功能。

7. **专门的 JSPI 安装函数:**
   - 提供了 `InstallJSPromiseIntegration` 和 `InstallTypeReflection` 函数，用于更细粒度地控制 JSPI 和类型反射功能的安装。

**与 JavaScript 的关系和示例:**

这段 C++ 代码的目标是将 WebAssembly 的功能暴露给 JavaScript。它创建了 JavaScript 可以直接使用的构造函数和对象。

**例如：**

**WebAssembly.Module:**

```javascript
// 假设 wasmCode 是一个包含 WebAssembly 字节码的 ArrayBuffer
const wasmModule = new WebAssembly.Module(wasmCode);
console.log(wasmModule.exports); // 获取模块的导出
```
这段 C++ 代码中的 `InstallConstructorFunc` 和 `SetupConstructor` 调用创建了 `WebAssembly.Module` 构造函数，使得 JavaScript 可以使用 `new WebAssembly.Module()` 创建 WebAssembly 模块实例。`InstallFunc` 调用则将 C++ 实现的 `wasm::WebAssemblyModuleExports` 函数连接到 JavaScript 的 `module.exports` 属性上。

**WebAssembly.Memory:**

```javascript
const memory = new WebAssembly.Memory({ initial: 1 });
const buffer = memory.buffer;
const uint8Array = new Uint8Array(buffer);
uint8Array[0] = 42;
console.log(uint8Array[0]); // 输出 42
memory.grow(1); // 增加内存大小
```
`InstallConstructorFunc` 和 `SetupConstructor` 创建了 `WebAssembly.Memory` 构造函数。`InstallGetter` 将 C++ 的 `wasm::WebAssemblyMemoryGetBuffer` 函数连接到 `memory.buffer` 属性，`InstallFunc` 将 `wasm::WebAssemblyMemoryGrow` 连接到 `memory.grow()` 方法。

**WebAssembly.Table:**

```javascript
const table = new WebAssembly.Table({ initial: 2, element: 'anyfunc' });
// ...
```
类似地，`InstallConstructorFunc` 和 `SetupConstructor` 创建了 `WebAssembly.Table` 构造函数。`InstallGetter` 和 `InstallFunc` 将 C++ 函数连接到 `table.length`、`table.grow`、`table.set` 和 `table.get` 方法。

**WebAssembly.Global:**

```javascript
const global = new WebAssembly.Global({ value: 42, mutable: true });
console.log(global.value); // 输出 42
global.value = 100;
console.log(global.value); // 输出 100
```
这段代码中的设置确保 JavaScript 可以创建和操作 `WebAssembly.Global` 对象，并通过 `value` 属性访问和修改其值。

**WebAssembly.compileStreaming 和 WebAssembly.instantiateStreaming:**

```javascript
fetch('my.wasm')
  .then(response => WebAssembly.compileStreaming(response))
  .then(module => {
    // 使用 module
  });

fetch('my.wasm')
  .then(response => WebAssembly.instantiateStreaming(response))
  .then(instance => {
    // 使用 instance
  });
```
如果启用了流式编译，这段 C++ 代码会将 `WebAssemblyCompileStreaming` 和 `WebAssemblyInstantiateStreaming` 函数连接到 JavaScript 的全局 `WebAssembly` 对象上，使得 JavaScript 可以异步地编译和实例化 WebAssembly 模块。

**类型反射的示例 (如果启用):**

```javascript
const memory = new WebAssembly.Memory({ initial: 1 });
console.log(memory.type()); // 输出类似 { type: 'memory', initial: 1, maximum: undefined } 的对象

function wasmFunc() {}
const func = new WebAssembly.Function({}, wasmFunc);
console.log(func.type()); // 输出类似 { type: 'function', parameters: [], results: [] } 的对象
```
`InstallTypeReflection` 函数会将 C++ 函数连接到这些 `type()` 方法，使得 JavaScript 能够获取 WebAssembly 对象的类型信息。

总而言之，这部分 C++ 代码是 V8 引擎中至关重要的一部分，它将底层的 WebAssembly 实现桥接到 JavaScript 环境，使得开发者可以使用 JavaScript API 来加载、编译、实例化和与 WebAssembly 模块进行交互。它还负责按需启用和安装一些高级的 WebAssembly 功能，提升了 WebAssembly 与 JavaScript 的集成度和灵活性。

Prompt: 
```
这是目录为v8/src/wasm/wasm-js.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
or, WASM_TABLE_OBJECT_TYPE,
                         WasmTableObject::kHeaderSize, "WebAssembly.Table");
    native_context->set_wasm_table_constructor(*table_constructor);
    InstallGetter(isolate, table_proto, "length",
                  wasm::WebAssemblyTableGetLength);
    InstallFunc(isolate, table_proto, "grow", wasm::WebAssemblyTableGrow, 1);
    InstallFunc(isolate, table_proto, "set", wasm::WebAssemblyTableSet, 1);
    InstallFunc(isolate, table_proto, "get", wasm::WebAssemblyTableGet, 1,
                false, NONE, SideEffectType::kHasNoSideEffect);
  }

  // Create the Memory object.
  {
    Handle<JSFunction> memory_constructor = InstallConstructorFunc(
        isolate, webassembly, "Memory", wasm::WebAssemblyMemory);
    Handle<JSObject> memory_proto =
        SetupConstructor(isolate, memory_constructor, WASM_MEMORY_OBJECT_TYPE,
                         WasmMemoryObject::kHeaderSize, "WebAssembly.Memory");
    native_context->set_wasm_memory_constructor(*memory_constructor);
    InstallFunc(isolate, memory_proto, "grow", wasm::WebAssemblyMemoryGrow, 1);
    InstallGetter(isolate, memory_proto, "buffer",
                  wasm::WebAssemblyMemoryGetBuffer);
  }

  // Create the Global object.
  {
    Handle<JSFunction> global_constructor = InstallConstructorFunc(
        isolate, webassembly, "Global", wasm::WebAssemblyGlobal);
    Handle<JSObject> global_proto =
        SetupConstructor(isolate, global_constructor, WASM_GLOBAL_OBJECT_TYPE,
                         WasmGlobalObject::kHeaderSize, "WebAssembly.Global");
    native_context->set_wasm_global_constructor(*global_constructor);
    InstallFunc(isolate, global_proto, "valueOf",
                wasm::WebAssemblyGlobalValueOf, 0, false, NONE,
                SideEffectType::kHasNoSideEffect);
    InstallGetterSetter(isolate, global_proto, "value",
                        wasm::WebAssemblyGlobalGetValue,
                        wasm::WebAssemblyGlobalSetValue);
  }

  // Create the Exception object.
  {
    Handle<JSFunction> tag_constructor = InstallConstructorFunc(
        isolate, webassembly, "Tag", wasm::WebAssemblyTag);
    SetupConstructor(isolate, tag_constructor, WASM_TAG_OBJECT_TYPE,
                     WasmTagObject::kHeaderSize, "WebAssembly.Tag");
    native_context->set_wasm_tag_constructor(*tag_constructor);
    auto js_tag = WasmExceptionTag::New(isolate, 0);
    // Note the canonical_type_index is reset in WasmJs::Install s.t.
    // type_canonicalizer bookkeeping remains valid.
    static constexpr wasm::CanonicalTypeIndex kInitialCanonicalTypeIndex{0};
    DirectHandle<JSObject> js_tag_object = WasmTagObject::New(
        isolate, &kWasmExceptionTagSignature, kInitialCanonicalTypeIndex,
        js_tag, Handle<WasmTrustedInstanceData>());
    native_context->set_wasm_js_tag(*js_tag_object);
    JSObject::AddProperty(isolate, webassembly, "JSTag", js_tag_object,
                          ro_attributes);
  }

  // Set up the runtime exception constructor.
  {
    Handle<JSFunction> exception_constructor = InstallConstructorFunc(
        isolate, webassembly, "Exception", wasm::WebAssemblyException);
    SetDummyInstanceTemplate(isolate, exception_constructor);
    Handle<JSObject> exception_proto = SetupConstructor(
        isolate, exception_constructor, WASM_EXCEPTION_PACKAGE_TYPE,
        WasmExceptionPackage::kSize, "WebAssembly.Exception",
        WasmExceptionPackage::kInObjectFieldCount);
    InstallFunc(isolate, exception_proto, "getArg",
                wasm::WebAssemblyExceptionGetArg, 2);
    InstallFunc(isolate, exception_proto, "is", wasm::WebAssemblyExceptionIs,
                1);
    native_context->set_wasm_exception_constructor(*exception_constructor);

    DirectHandle<Map> initial_map(exception_constructor->initial_map(),
                                  isolate);
    Map::EnsureDescriptorSlack(isolate, initial_map, 2);
    {
      Descriptor d = Descriptor::DataField(
          isolate, f->wasm_exception_tag_symbol(),
          WasmExceptionPackage::kTagIndex, DONT_ENUM, Representation::Tagged());
      initial_map->AppendDescriptor(isolate, &d);
    }
    {
      Descriptor d =
          Descriptor::DataField(isolate, f->wasm_exception_values_symbol(),
                                WasmExceptionPackage::kValuesIndex, DONT_ENUM,
                                Representation::Tagged());
      initial_map->AppendDescriptor(isolate, &d);
    }
  }

  // By default, make all exported functions an instance of {Function}.
  {
    DirectHandle<Map> function_map =
        isolate->sloppy_function_without_prototype_map();
    native_context->set_wasm_exported_function_map(*function_map);
  }

  // Setup errors.
  {
    DirectHandle<JSFunction> compile_error(
        native_context->wasm_compile_error_function(), isolate);
    JSObject::AddProperty(isolate, webassembly, f->CompileError_string(),
                          compile_error, DONT_ENUM);
    DirectHandle<JSFunction> link_error(
        native_context->wasm_link_error_function(), isolate);
    JSObject::AddProperty(isolate, webassembly, f->LinkError_string(),
                          link_error, DONT_ENUM);
    DirectHandle<JSFunction> runtime_error(
        native_context->wasm_runtime_error_function(), isolate);
    JSObject::AddProperty(isolate, webassembly, f->RuntimeError_string(),
                          runtime_error, DONT_ENUM);
  }
}

void WasmJs::InstallModule(Isolate* isolate, Handle<JSObject> webassembly) {
  Handle<JSGlobalObject> global = isolate->global_object();
  Handle<NativeContext> native_context(global->native_context(), isolate);

  Handle<JSFunction> module_constructor;
  if (v8_flags.js_source_phase_imports) {
    Handle<FunctionTemplateInfo>
        intrinsic_abstract_module_source_interface_template =
            NewFunctionTemplate(isolate, nullptr, false);
    Handle<JSObject> abstract_module_source_prototype = Handle<JSObject>(
        native_context->abstract_module_source_prototype(), isolate);
    ApiNatives::AddDataProperty(
        isolate, intrinsic_abstract_module_source_interface_template,
        v8_str(isolate, "prototype"), abstract_module_source_prototype, NONE);

    // Check that this is a reinstallation of the Module object.
    Handle<String> name = v8_str(isolate, "Module");
    CHECK(
        JSObject::HasRealNamedProperty(isolate, webassembly, name).ToChecked());
    // Reinstall the Module object with AbstractModuleSource as prototype.
    module_constructor =
        CreateFunc(isolate, name, wasm::WebAssemblyModule, true,
                   SideEffectType::kHasNoSideEffect,
                   intrinsic_abstract_module_source_interface_template);
    module_constructor->shared()->set_length(1);
    JSObject::SetOwnPropertyIgnoreAttributes(webassembly, name,
                                             module_constructor, DONT_ENUM)
        .Assert();
  } else {
    module_constructor = InstallConstructorFunc(isolate, webassembly, "Module",
                                                wasm::WebAssemblyModule);
  }
  SetupConstructor(isolate, module_constructor, WASM_MODULE_OBJECT_TYPE,
                   WasmModuleObject::kHeaderSize, "WebAssembly.Module");
  native_context->set_wasm_module_constructor(*module_constructor);

  InstallFunc(isolate, module_constructor, "imports",
              wasm::WebAssemblyModuleImports, 1, false, NONE,
              SideEffectType::kHasNoSideEffect);
  InstallFunc(isolate, module_constructor, "exports",
              wasm::WebAssemblyModuleExports, 1, false, NONE,
              SideEffectType::kHasNoSideEffect);
  InstallFunc(isolate, module_constructor, "customSections",
              wasm::WebAssemblyModuleCustomSections, 2, false, NONE,
              SideEffectType::kHasNoSideEffect);
}

// static
void WasmJs::Install(Isolate* isolate) {
  Handle<JSGlobalObject> global = isolate->global_object();
  DirectHandle<NativeContext> native_context(global->native_context(), isolate);

  if (native_context->is_wasm_js_installed() != Smi::zero()) return;
  native_context->set_is_wasm_js_installed(Smi::FromInt(1));

  // We always use the WebAssembly object from the native context; as this code
  // is executed before any user code, this is expected to be the same as the
  // global "WebAssembly" property. But even later during execution we always
  // want to use this preallocated object instead of whatever user code
  // installed as "WebAssembly" property.
  Handle<JSObject> webassembly(native_context->wasm_webassembly_object(),
                               isolate);
  if (v8_flags.js_source_phase_imports) {
    // Reinstall the Module object with the experimental interface.
    InstallModule(isolate, webassembly);
  }

  // Expose the API on the global object if not in jitless mode (with more
  // subtleties).
  //
  // Even in interpreter-only mode, wasm currently still creates executable
  // memory at runtime. Unexpose wasm until this changes.
  // The correctness fuzzers are a special case: many of their test cases are
  // built by fetching a random property from the the global object, and thus
  // the global object layout must not change between configs. That is why we
  // continue exposing wasm on correctness fuzzers even in jitless mode.
  // TODO(jgruber): Remove this once / if wasm can run without executable
  // memory.
  bool expose_wasm = !i::v8_flags.jitless ||
                     i::v8_flags.correctness_fuzzer_suppressions ||
                     i::v8_flags.wasm_jitless;
  if (expose_wasm) {
    Handle<String> WebAssembly_string = v8_str(isolate, "WebAssembly");
    JSObject::AddProperty(isolate, global, WebAssembly_string, webassembly,
                          DONT_ENUM);
  }

  {
    // Reset the JSTag's canonical_type_index based on this Isolate's
    // type_canonicalizer.
    DirectHandle<WasmTagObject> js_tag_object(
        Cast<WasmTagObject>(native_context->wasm_js_tag()), isolate);
    js_tag_object->set_canonical_type_index(
        wasm::GetWasmEngine()
            ->type_canonicalizer()
            ->AddRecursiveGroup(&kWasmExceptionTagSignature)
            .index);
  }

  if (v8_flags.wasm_test_streaming) {
    isolate->set_wasm_streaming_callback(WasmStreamingCallbackForTesting);
  }

  if (isolate->wasm_streaming_callback() != nullptr) {
    InstallFunc(isolate, webassembly, "compileStreaming",
                WebAssemblyCompileStreaming, 1);
    InstallFunc(isolate, webassembly, "instantiateStreaming",
                WebAssemblyInstantiateStreaming, 1);
  }

  // The native_context is not set up completely yet. That's why we cannot use
  // {WasmEnabledFeatures::FromIsolate} and have to use
  // {WasmEnabledFeatures::FromFlags} instead.
  const auto enabled_features = wasm::WasmEnabledFeatures::FromFlags();

  if (enabled_features.has_type_reflection()) {
    InstallTypeReflection(isolate, native_context, webassembly);
  }

  // Initialize and install JSPI feature.
  if (enabled_features.has_jspi()) {
    CHECK(native_context->is_wasm_jspi_installed() == Smi::zero());
    isolate->WasmInitJSPIFeature();
    InstallJSPromiseIntegration(isolate, native_context, webassembly);
    native_context->set_is_wasm_jspi_installed(Smi::FromInt(1));
  } else if (v8_flags.stress_wasm_stack_switching) {
    // Set up the JSPI objects necessary for stress-testing stack-switching, but
    // don't install WebAssembly.promising and WebAssembly.Suspending.
    isolate->WasmInitJSPIFeature();
  }
}

// static
void WasmJs::InstallConditionalFeatures(Isolate* isolate,
                                        Handle<NativeContext> context) {
  Handle<JSObject> webassembly{context->wasm_webassembly_object(), isolate};
  if (!webassembly->map()->is_extensible()) return;
  if (webassembly->map()->is_access_check_needed()) return;

  // If you need to install some optional features, follow the pattern:
  //
  // if (isolate->IsMyWasmFeatureEnabled(context)) {
  //   Handle<String> feature = isolate->factory()->...;
  //   if (!JSObject::HasRealNamedProperty(isolate, webassembly, feature)
  //            .FromMaybe(true)) {
  //     InstallFeature(isolate, webassembly);
  //   }
  // }

  // Install JSPI-related features.
  if (isolate->IsWasmJSPIRequested(context)) {
    if (context->is_wasm_jspi_installed() == Smi::zero()) {
      isolate->WasmInitJSPIFeature();
      if (InstallJSPromiseIntegration(isolate, context, webassembly) &&
          InstallTypeReflection(isolate, context, webassembly)) {
        context->set_is_wasm_jspi_installed(Smi::FromInt(1));
      }
    }
  }
}

// static
// Return true if this call results in JSPI being installed.
bool WasmJs::InstallJSPromiseIntegration(Isolate* isolate,
                                         DirectHandle<NativeContext> context,
                                         Handle<JSObject> webassembly) {
  Handle<String> suspender_string = v8_str(isolate, "Suspender");
  if (JSObject::HasRealNamedProperty(isolate, webassembly, suspender_string)
          .FromMaybe(true)) {
    return false;
  }
  Handle<String> suspending_string = v8_str(isolate, "Suspending");
  if (JSObject::HasRealNamedProperty(isolate, webassembly, suspending_string)
          .FromMaybe(true)) {
    return false;
  }
  Handle<String> promising_string = v8_str(isolate, "promising");
  if (JSObject::HasRealNamedProperty(isolate, webassembly, promising_string)
          .FromMaybe(true)) {
    return false;
  }
  Handle<JSFunction> suspending_constructor = InstallConstructorFunc(
      isolate, webassembly, "Suspending", WebAssemblySuspendingImpl);
  context->set_wasm_suspending_constructor(*suspending_constructor);
  SetupConstructor(isolate, suspending_constructor, WASM_SUSPENDING_OBJECT_TYPE,
                   WasmSuspendingObject::kHeaderSize, "WebAssembly.Suspending");
  InstallFunc(isolate, webassembly, "promising", WebAssemblyPromising, 1);
  return true;
}

// Return true only if this call resulted in installation of type reflection.
// static
bool WasmJs::InstallTypeReflection(Isolate* isolate,
                                   DirectHandle<NativeContext> context,
                                   Handle<JSObject> webassembly) {
  // Extensibility of the `WebAssembly` object should already have been checked
  // by the caller.
  DCHECK(webassembly->map()->is_extensible());

  // First check if any of the type reflection fields already exist. If so, bail
  // out and don't install any new fields.
  if (JSObject::HasRealNamedProperty(isolate, webassembly,
                                     isolate->factory()->Function_string())
          .FromMaybe(true)) {
    return false;
  }

  auto GetProto = [isolate](Tagged<JSFunction> constructor) {
    return handle(Cast<JSObject>(constructor->instance_prototype()), isolate);
  };
  Handle<JSObject> table_proto = GetProto(context->wasm_table_constructor());
  Handle<JSObject> global_proto = GetProto(context->wasm_global_constructor());
  Handle<JSObject> memory_proto = GetProto(context->wasm_memory_constructor());
  Handle<JSObject> tag_proto = GetProto(context->wasm_tag_constructor());

  Handle<String> type_string = v8_str(isolate, "type");
  auto CheckProto = [isolate, type_string](Handle<JSObject> proto) {
    if (JSObject::HasRealNamedProperty(isolate, proto, type_string)
            .FromMaybe(true)) {
      return false;
    }
    // Also check extensibility, otherwise adding properties will fail.
    if (!proto->map()->is_extensible()) return false;
    return true;
  };
  if (!CheckProto(table_proto)) return false;
  if (!CheckProto(global_proto)) return false;
  if (!CheckProto(memory_proto)) return false;
  if (!CheckProto(tag_proto)) return false;

  // Checks are done, start installing the new fields.
  InstallFunc(isolate, table_proto, type_string, WebAssemblyTableType, 0, false,
              NONE, SideEffectType::kHasNoSideEffect);
  InstallFunc(isolate, memory_proto, type_string, WebAssemblyMemoryType, 0,
              false, NONE, SideEffectType::kHasNoSideEffect);
  InstallFunc(isolate, global_proto, type_string, WebAssemblyGlobalType, 0,
              false, NONE, SideEffectType::kHasNoSideEffect);
  InstallFunc(isolate, tag_proto, type_string, WebAssemblyTagType, 0, false,
              NONE, SideEffectType::kHasNoSideEffect);

  // Create the Function object.
  Handle<JSFunction> function_constructor = InstallConstructorFunc(
      isolate, webassembly, "Function", WebAssemblyFunction);
  SetDummyInstanceTemplate(isolate, function_constructor);
  JSFunction::EnsureHasInitialMap(function_constructor);
  Handle<JSObject> function_proto(
      Cast<JSObject>(function_constructor->instance_prototype()), isolate);
  Handle<Map> function_map =
      Map::Copy(isolate, isolate->sloppy_function_without_prototype_map(),
                "WebAssembly.Function");
  CHECK(JSObject::SetPrototype(
            isolate, function_proto,
            handle(context->function_function()->prototype(), isolate), false,
            kDontThrow)
            .FromJust());
  JSFunction::SetInitialMap(isolate, function_constructor, function_map,
                            function_proto);

  constexpr PropertyAttributes ro_attributes =
      static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY);
  JSObject::AddProperty(isolate, function_proto,
                        isolate->factory()->to_string_tag_symbol(),
                        v8_str(isolate, "WebAssembly.Function"), ro_attributes);

  InstallFunc(isolate, function_proto, type_string, WebAssemblyFunctionType, 0);
  SimpleInstallFunction(isolate, function_proto, "bind",
                        Builtin::kWebAssemblyFunctionPrototypeBind, 1,
                        kDontAdapt);
  // Make all exported functions an instance of {WebAssembly.Function}.
  context->set_wasm_exported_function_map(*function_map);
  return true;
}

namespace wasm {
// static
std::unique_ptr<WasmStreaming> StartStreamingForTesting(
    Isolate* isolate,
    std::shared_ptr<wasm::CompilationResultResolver> resolver) {
  return std::make_unique<WasmStreaming>(
      std::make_unique<WasmStreaming::WasmStreamingImpl>(
          isolate, "StartStreamingForTesting", CompileTimeImports{}, resolver));
}
}  // namespace wasm

#undef ASSIGN
#undef EXTRACT_THIS

}  // namespace internal
}  // namespace v8

"""


```