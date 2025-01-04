Response: The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/api/api.cc`.
This is the second part of an 8-part file. The code seems to focus on:

1. **Object Templates and Interceptors:** Defining how JavaScript objects created from templates can intercept property access (get, set, query, etc.).
2. **Scripts and Modules:**  Handling the compilation, execution, and management of JavaScript code, including both classic scripts and ES modules. This includes caching, streaming, and error handling.
3. **Exception Handling:**  Implementing `TryCatch` blocks for capturing and managing JavaScript exceptions.
4. **Message Handling:** Providing information about errors and exceptions that occur during JavaScript execution.

To illustrate the JavaScript relationship, I can provide examples for Object Templates with interceptors, running scripts, handling exceptions, and accessing message details.
这是 `v8/src/api/api.cc` 文件的一部分，主要负责 V8 API 中与以下功能相关的实现：

**1. 对象模板 (Object Templates) 和拦截器 (Interceptors):**

*   **功能归纳:**  这部分代码定义了如何创建和配置对象模板，以及如何为这些模板设置属性访问拦截器。拦截器允许 C++ 代码在 JavaScript 代码尝试访问或修改对象的属性时进行干预，执行自定义逻辑。这包括处理命名属性和索引属性的获取 (getter)、设置 (setter)、查询 (query)、描述 (descriptor)、删除 (deleter)、枚举 (enumerator) 和定义 (definer) 等操作。
*   **与 JavaScript 的关系:**  对象模板是创建具有特定结构和行为的 JavaScript 对象的蓝图。拦截器允许开发者在 JavaScript 层面实现更底层的对象属性访问控制和自定义行为。

    **JavaScript 示例:**

    ```javascript
    // C++ (在 ObjectTemplate::SetHandler 中设置拦截器)
    void MyNamedPropertyGetter(Local<Name> property, const PropertyCallbackInfo<Value>& info) {
      Local<Context> context = info.GetIsolate()->GetCurrentContext();
      info.GetReturnValue().Set(String::NewFromUtf8(info.GetIsolate(), "Intercepted!"));
    }

    void SetUpObjectTemplate(Local<Isolate> isolate, Local<ObjectTemplate> templ) {
      NamedPropertyHandlerConfiguration config(MyNamedPropertyGetter);
      templ->SetHandler(config);
    }

    // JavaScript
    let myObject = objectTemplate.NewInstance(context).Get();
    console.log(myObject.someProperty); // 输出 "Intercepted!"，因为拦截器覆盖了默认的属性获取行为。
    ```

**2. 脚本 (Scripts) 和模块 (Modules) 的编译和执行:**

*   **功能归纳:** 这部分代码处理 JavaScript 代码的编译 (包括从字符串或流中编译)、绑定到特定上下文、执行，以及获取脚本的元数据 (如 ID、行号、列号、名称、URL 等)。它还处理 ES 模块的加载、实例化和评估，包括模块请求的处理和模块命名空间的获取。此外，还涉及到编译缓存 (CachedData) 的创建和使用，以及异步编译和代码缓存加载 (ScriptStreamingTask, ConsumeCodeCacheTask)。
*   **与 JavaScript 的关系:**  `Script` 和 `Module` 对象代表了 JavaScript 代码的不同组织形式。这些 API 允许在 V8 引擎中加载、编译和运行 JavaScript 代码。

    **JavaScript 示例:**

    ```javascript
    // 编译并执行脚本
    const script = new v8.Script('console.log("Hello from script!");');
    script.runInThisContext();

    // 编译并实例化模块
    const module = new v8.SourceTextModule('export function hello() { console.log("Hello from module!"); }');
    await module.link(resolve, reject);
    await module.evaluate();
    module.namespace.hello();
    ```

**3. 异常处理 (Exception Handling):**

*   **功能归纳:**  这部分实现了 `v8::TryCatch` 类，用于捕获和处理 JavaScript 代码执行期间抛出的异常。它提供了检查是否捕获到异常、获取异常信息、重新抛出异常以及获取异常堆栈信息等功能。
*   **与 JavaScript 的关系:**  `TryCatch` 机制允许 C++ 代码安全地调用 JavaScript 代码，并处理可能发生的错误，防止程序崩溃。

    **JavaScript 示例:**

    ```javascript
    // C++
    TryCatch tryCatch(isolate);
    Local<Value> result = script->Run(context).ToLocalChecked();
    if (tryCatch.HasCaught()) {
      Local<Message> message = tryCatch.Message();
      String::Utf8Value error(isolate, message->Get());
      printf("Caught exception: %s\n", *error);
    }

    // JavaScript (可能导致异常的代码)
    throw new Error("Something went wrong!");
    ```

**4. 消息 (Message) 处理:**

*   **功能归纳:**  这部分定义了 `v8::Message` 类，用于表示 JavaScript 执行期间产生的错误或警告信息。它提供了获取消息文本、脚本资源名称、行号、列号、堆栈信息等功能。
*   **与 JavaScript 的关系:**  当 JavaScript 代码执行出错时，V8 引擎会生成 `Message` 对象，其中包含了错误的详细信息，这些信息可以被 C++ 代码捕获和分析，用于日志记录、调试等目的。

    **JavaScript 示例:**

    ```javascript
    // C++ (在 TryCatch 中获取 Message 对象)
    if (tryCatch.HasCaught()) {
      Local<Message> message = tryCatch.Message();
      String::Utf8Value origin(isolate, message->GetScriptResourceName());
      int lineNumber = message->GetLineNumber(context).FromJust();
      String::Utf8Value errorText(isolate, message->Get());
      printf("Error in %s at line %d: %s\n", *origin, lineNumber, *errorText);
    }

    // JavaScript (导致错误的代码)
    console.log(nonExistentVariable); // 引用未定义的变量会产生错误消息。
    ```

总而言之，这部分 `api.cc` 代码是 V8 引擎与外部 C++ 代码交互的关键桥梁，它提供了创建和操作 JavaScript 对象、执行代码、处理错误以及获取运行时信息的底层机制。这些功能是构建基于 V8 的应用程序和嵌入式 JavaScript 引擎的基础。

Prompt: 
```
这是目录为v8/src/api/api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共8部分，请归纳一下它的功能

"""
andle(*name),
                                 intrinsic,
                                 static_cast<i::PropertyAttributes>(attribute));
}

namespace {
enum class PropertyType { kNamed, kIndexed };
template <PropertyType property_type, typename Getter, typename Setter,
          typename Query, typename Descriptor, typename Deleter,
          typename Enumerator, typename Definer>
i::Handle<i::InterceptorInfo> CreateInterceptorInfo(
    i::Isolate* i_isolate, Getter getter, Setter setter, Query query,
    Descriptor descriptor, Deleter remover, Enumerator enumerator,
    Definer definer, Local<Value> data,
    base::Flags<PropertyHandlerFlags> flags) {
  // TODO(saelo): instead of an in-sandbox struct with a lot of external
  // pointers (with different tags), consider creating an object in trusted
  // space instead. That way, only a single reference going out of the sandbox
  // would be required.
  auto obj = i::Cast<i::InterceptorInfo>(i_isolate->factory()->NewStruct(
      i::INTERCEPTOR_INFO_TYPE, i::AllocationType::kOld));
  obj->set_flags(0);

#define CALLBACK_TAG(NAME)                             \
  property_type == PropertyType::kNamed                \
      ? internal::kApiNamedProperty##NAME##CallbackTag \
      : internal::kApiIndexedProperty##NAME##CallbackTag;

  if (getter != nullptr) {
    constexpr internal::ExternalPointerTag tag = CALLBACK_TAG(Getter);
    SET_FIELD_WRAPPED(i_isolate, obj, set_getter, getter, tag);
  }
  if (setter != nullptr) {
    constexpr internal::ExternalPointerTag tag = CALLBACK_TAG(Setter);
    SET_FIELD_WRAPPED(i_isolate, obj, set_setter, setter, tag);
  }
  if (query != nullptr) {
    constexpr internal::ExternalPointerTag tag = CALLBACK_TAG(Query);
    SET_FIELD_WRAPPED(i_isolate, obj, set_query, query, tag);
  }
  if (descriptor != nullptr) {
    constexpr internal::ExternalPointerTag tag = CALLBACK_TAG(Descriptor);
    SET_FIELD_WRAPPED(i_isolate, obj, set_descriptor, descriptor, tag);
  }
  if (remover != nullptr) {
    constexpr internal::ExternalPointerTag tag = CALLBACK_TAG(Deleter);
    SET_FIELD_WRAPPED(i_isolate, obj, set_deleter, remover, tag);
  }
  if (enumerator != nullptr) {
    SET_FIELD_WRAPPED(i_isolate, obj, set_enumerator, enumerator,
                      internal::kApiIndexedPropertyEnumeratorCallbackTag);
  }
  if (definer != nullptr) {
    constexpr internal::ExternalPointerTag tag = CALLBACK_TAG(Definer);
    SET_FIELD_WRAPPED(i_isolate, obj, set_definer, definer, tag);
  }

#undef CALLBACK_TAG

  obj->set_can_intercept_symbols(
      !(flags & PropertyHandlerFlags::kOnlyInterceptStrings));
  obj->set_non_masking(flags & PropertyHandlerFlags::kNonMasking);
  obj->set_has_no_side_effect(flags & PropertyHandlerFlags::kHasNoSideEffect);

  if (data.IsEmpty()) {
    data = v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate));
  }
  obj->set_data(*Utils::OpenDirectHandle(*data));
  return obj;
}

template <typename Getter, typename Setter, typename Query, typename Descriptor,
          typename Deleter, typename Enumerator, typename Definer>
i::Handle<i::InterceptorInfo> CreateNamedInterceptorInfo(
    i::Isolate* i_isolate, Getter getter, Setter setter, Query query,
    Descriptor descriptor, Deleter remover, Enumerator enumerator,
    Definer definer, Local<Value> data,
    base::Flags<PropertyHandlerFlags> flags) {
  auto interceptor = CreateInterceptorInfo<PropertyType::kNamed>(
      i_isolate, getter, setter, query, descriptor, remover, enumerator,
      definer, data, flags);
  interceptor->set_is_named(true);
  return interceptor;
}

template <typename Getter, typename Setter, typename Query, typename Descriptor,
          typename Deleter, typename Enumerator, typename Definer>
i::Handle<i::InterceptorInfo> CreateIndexedInterceptorInfo(
    i::Isolate* i_isolate, Getter getter, Setter setter, Query query,
    Descriptor descriptor, Deleter remover, Enumerator enumerator,
    Definer definer, Local<Value> data,
    base::Flags<PropertyHandlerFlags> flags) {
  auto interceptor = CreateInterceptorInfo<PropertyType::kIndexed>(
      i_isolate, getter, setter, query, descriptor, remover, enumerator,
      definer, data, flags);
  interceptor->set_is_named(false);
  return interceptor;
}

template <typename Getter, typename Setter, typename Query, typename Descriptor,
          typename Deleter, typename Enumerator, typename Definer>
void ObjectTemplateSetNamedPropertyHandler(
    ObjectTemplate* templ, Getter getter, Setter setter, Query query,
    Descriptor descriptor, Deleter remover, Enumerator enumerator,
    Definer definer, Local<Value> data, PropertyHandlerFlags flags) {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(templ)->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  auto cons = EnsureConstructor(i_isolate, templ);
  EnsureNotPublished(cons, "ObjectTemplateSetNamedPropertyHandler");
  auto obj =
      CreateNamedInterceptorInfo(i_isolate, getter, setter, query, descriptor,
                                 remover, enumerator, definer, data, flags);
  i::FunctionTemplateInfo::SetNamedPropertyHandler(i_isolate, cons, obj);
}
}  // namespace

void ObjectTemplate::SetHandler(
    const NamedPropertyHandlerConfiguration& config) {
  ObjectTemplateSetNamedPropertyHandler(
      this, config.getter, config.setter, config.query, config.descriptor,
      config.deleter, config.enumerator, config.definer, config.data,
      config.flags);
}

void ObjectTemplate::MarkAsUndetectable() {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  auto cons = EnsureConstructor(i_isolate, this);
  EnsureNotPublished(cons, "v8::ObjectTemplate::MarkAsUndetectable");
  cons->set_undetectable(true);
}

void ObjectTemplate::SetAccessCheckCallback(AccessCheckCallback callback,
                                            Local<Value> data) {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  auto cons = EnsureConstructor(i_isolate, this);
  EnsureNotPublished(cons, "v8::ObjectTemplate::SetAccessCheckCallback");

  i::Handle<i::Struct> struct_info = i_isolate->factory()->NewStruct(
      i::ACCESS_CHECK_INFO_TYPE, i::AllocationType::kOld);
  auto info = i::Cast<i::AccessCheckInfo>(struct_info);

  SET_FIELD_WRAPPED(i_isolate, info, set_callback, callback,
                    internal::kApiAccessCheckCallbackTag);
  info->set_named_interceptor(i::Smi::zero());
  info->set_indexed_interceptor(i::Smi::zero());

  if (data.IsEmpty()) {
    data = v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate));
  }
  info->set_data(*Utils::OpenDirectHandle(*data));

  i::FunctionTemplateInfo::SetAccessCheckInfo(i_isolate, cons, info);
  cons->set_needs_access_check(true);
}

void ObjectTemplate::SetAccessCheckCallbackAndHandler(
    AccessCheckCallback callback,
    const NamedPropertyHandlerConfiguration& named_handler,
    const IndexedPropertyHandlerConfiguration& indexed_handler,
    Local<Value> data) {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  auto cons = EnsureConstructor(i_isolate, this);
  EnsureNotPublished(cons,
                     "v8::ObjectTemplate::SetAccessCheckCallbackWithHandler");

  i::Handle<i::Struct> struct_info = i_isolate->factory()->NewStruct(
      i::ACCESS_CHECK_INFO_TYPE, i::AllocationType::kOld);
  auto info = i::Cast<i::AccessCheckInfo>(struct_info);

  SET_FIELD_WRAPPED(i_isolate, info, set_callback, callback,
                    internal::kApiAccessCheckCallbackTag);
  auto named_interceptor = CreateNamedInterceptorInfo(
      i_isolate, named_handler.getter, named_handler.setter,
      named_handler.query, named_handler.descriptor, named_handler.deleter,
      named_handler.enumerator, named_handler.definer, named_handler.data,
      named_handler.flags);
  info->set_named_interceptor(*named_interceptor);
  auto indexed_interceptor = CreateIndexedInterceptorInfo(
      i_isolate, indexed_handler.getter, indexed_handler.setter,
      indexed_handler.query, indexed_handler.descriptor,
      indexed_handler.deleter, indexed_handler.enumerator,
      indexed_handler.definer, indexed_handler.data, indexed_handler.flags);
  info->set_indexed_interceptor(*indexed_interceptor);

  if (data.IsEmpty()) {
    data = v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate));
  }
  info->set_data(*Utils::OpenDirectHandle(*data));

  i::FunctionTemplateInfo::SetAccessCheckInfo(i_isolate, cons, info);
  cons->set_needs_access_check(true);
}

void ObjectTemplate::SetHandler(
    const IndexedPropertyHandlerConfiguration& config) {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  auto cons = EnsureConstructor(i_isolate, this);
  EnsureNotPublished(cons, "v8::ObjectTemplate::SetHandler");
  auto obj = CreateIndexedInterceptorInfo(
      i_isolate, config.getter, config.setter, config.query, config.descriptor,
      config.deleter, config.enumerator, config.definer, config.data,
      config.flags);
  i::FunctionTemplateInfo::SetIndexedPropertyHandler(i_isolate, cons, obj);
}

void ObjectTemplate::SetCallAsFunctionHandler(FunctionCallback callback,
                                              Local<Value> data) {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  auto cons = EnsureConstructor(i_isolate, this);
  EnsureNotPublished(cons, "v8::ObjectTemplate::SetCallAsFunctionHandler");
  DCHECK_NOT_NULL(callback);

  // This template is just a container for callback and data values and thus
  // it's not supposed to be instantiated. Don't cache it.
  constexpr bool do_not_cache = true;
  constexpr int length = 0;
  i::Handle<i::FunctionTemplateInfo> templ =
      i_isolate->factory()->NewFunctionTemplateInfo(length, do_not_cache);
  templ->set_is_object_template_call_handler(true);
  Utils::ToLocal(templ)->SetCallHandler(callback, data);
  i::FunctionTemplateInfo::SetInstanceCallHandler(i_isolate, cons, templ);
}

int ObjectTemplate::InternalFieldCount() const {
  return Utils::OpenDirectHandle(this)->embedder_field_count();
}

void ObjectTemplate::SetInternalFieldCount(int value) {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  if (!Utils::ApiCheck(i::Smi::IsValid(value),
                       "v8::ObjectTemplate::SetInternalFieldCount()",
                       "Invalid embedder field count")) {
    return;
  }
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (value > 0) {
    // The embedder field count is set by the constructor function's
    // construct code, so we ensure that there is a constructor
    // function to do the setting.
    EnsureConstructor(i_isolate, this);
  }
  Utils::OpenDirectHandle(this)->set_embedder_field_count(value);
}

bool ObjectTemplate::IsImmutableProto() const {
  return Utils::OpenDirectHandle(this)->immutable_proto();
}

void ObjectTemplate::SetImmutableProto() {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  self->set_immutable_proto(true);
}

bool ObjectTemplate::IsCodeLike() const {
  return Utils::OpenDirectHandle(this)->code_like();
}

void ObjectTemplate::SetCodeLike() {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  self->set_code_like(true);
}

Local<DictionaryTemplate> DictionaryTemplate::New(
    Isolate* isolate, MemorySpan<const std::string_view> names) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  API_RCS_SCOPE(i_isolate, DictionaryTemplate, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return Utils::ToLocal(i::DictionaryTemplateInfo::Create(i_isolate, names));
}

Local<Object> DictionaryTemplate::NewInstance(
    Local<Context> context, MemorySpan<MaybeLocal<Value>> property_values) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  API_RCS_SCOPE(i_isolate, DictionaryTemplate, NewInstance);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto self = Utils::OpenDirectHandle(this);
  return ToApiHandle<Object>(i::DictionaryTemplateInfo::NewInstance(
      Utils::OpenHandle(*context), self, property_values));
}

// --- S c r i p t s ---

// Internally, UnboundScript and UnboundModuleScript are SharedFunctionInfos,
// and Script is a JSFunction.

ScriptCompiler::CachedData::CachedData(const uint8_t* data_, int length_,
                                       BufferPolicy buffer_policy_)
    : data(data_),
      length(length_),
      rejected(false),
      buffer_policy(buffer_policy_) {}

ScriptCompiler::CachedData::~CachedData() {
  if (buffer_policy == BufferOwned) {
    delete[] data;
  }
}

ScriptCompiler::CachedData::CompatibilityCheckResult
ScriptCompiler::CachedData::CompatibilityCheck(Isolate* isolate) {
  i::AlignedCachedData aligned(data, length);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i::SerializedCodeSanityCheckResult result;
  i::SerializedCodeData scd =
      i::SerializedCodeData::FromCachedDataWithoutSource(
          i_isolate->AsLocalIsolate(), &aligned, &result);
  return static_cast<ScriptCompiler::CachedData::CompatibilityCheckResult>(
      result);
}

ScriptCompiler::StreamedSource::StreamedSource(
    std::unique_ptr<ExternalSourceStream> stream, Encoding encoding)
    : impl_(new i::ScriptStreamingData(std::move(stream), encoding)) {}

ScriptCompiler::StreamedSource::~StreamedSource() = default;

Local<Script> UnboundScript::BindToCurrentContext() {
  auto function_info = Utils::OpenHandle(this);
  // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is gone.
  DCHECK(!i::HeapLayout::InReadOnlySpace(*function_info));
  i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*function_info);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::DirectHandle<i::JSFunction> function =
      i::Factory::JSFunctionBuilder{i_isolate, function_info,
                                    i_isolate->native_context()}
          .Build();
  return ToApiHandle<Script>(function);
}

int UnboundScript::GetId() const {
  auto function_info = Utils::OpenDirectHandle(this);
  // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is gone.
  DCHECK(!i::HeapLayout::InReadOnlySpace(*function_info));
  API_RCS_SCOPE(i::GetIsolateFromWritableObject(*function_info), UnboundScript,
                GetId);
  return i::Cast<i::Script>(function_info->script())->id();
}

int UnboundScript::GetLineNumber(int code_pos) {
  auto obj = Utils::OpenDirectHandle(this);
  if (i::IsScript(obj->script())) {
    // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is
    // gone.
    DCHECK(!i::HeapLayout::InReadOnlySpace(*obj));
    i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    API_RCS_SCOPE(i_isolate, UnboundScript, GetLineNumber);
    i::DirectHandle<i::Script> script(i::Cast<i::Script>(obj->script()),
                                      i_isolate);
    return i::Script::GetLineNumber(script, code_pos);
  } else {
    return -1;
  }
}

int UnboundScript::GetColumnNumber(int code_pos) {
  auto obj = Utils::OpenDirectHandle(this);
  if (i::IsScript(obj->script())) {
    // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is
    // gone.
    DCHECK(!i::HeapLayout::InReadOnlySpace(*obj));
    i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    API_RCS_SCOPE(i_isolate, UnboundScript, GetColumnNumber);
    i::DirectHandle<i::Script> script(i::Cast<i::Script>(obj->script()),
                                      i_isolate);
    return i::Script::GetColumnNumber(script, code_pos);
  } else {
    return -1;
  }
}

Local<Value> UnboundScript::GetScriptName() {
  auto obj = Utils::OpenDirectHandle(this);
  if (i::IsScript(obj->script())) {
    // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is
    // gone.
    DCHECK(!i::HeapLayout::InReadOnlySpace(*obj));
    i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    API_RCS_SCOPE(i_isolate, UnboundScript, GetName);
    i::Tagged<i::Object> name = i::Cast<i::Script>(obj->script())->name();
    return Utils::ToLocal(i::direct_handle(name, i_isolate));
  } else {
    return Local<String>();
  }
}

Local<Value> UnboundScript::GetSourceURL() {
  auto obj = Utils::OpenDirectHandle(this);
  if (i::IsScript(obj->script())) {
    // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is
    // gone.
    DCHECK(!i::HeapLayout::InReadOnlySpace(*obj));
    i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
    API_RCS_SCOPE(i_isolate, UnboundScript, GetSourceURL);
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    i::Tagged<i::Object> url = i::Cast<i::Script>(obj->script())->source_url();
    return Utils::ToLocal(i::direct_handle(url, i_isolate));
  } else {
    return Local<String>();
  }
}

Local<Value> UnboundScript::GetSourceMappingURL() {
  auto obj = Utils::OpenDirectHandle(this);
  if (i::IsScript(obj->script())) {
    // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is
    // gone.
    DCHECK(!i::HeapLayout::InReadOnlySpace(*obj));
    i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
    API_RCS_SCOPE(i_isolate, UnboundScript, GetSourceMappingURL);
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    i::Tagged<i::Object> url =
        i::Cast<i::Script>(obj->script())->source_mapping_url();
    return Utils::ToLocal(i::direct_handle(url, i_isolate));
  } else {
    return Local<String>();
  }
}

Local<Value> UnboundModuleScript::GetSourceURL() {
  auto obj = Utils::OpenDirectHandle(this);
  if (i::IsScript(obj->script())) {
    // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is
    // gone.
    DCHECK(!i::HeapLayout::InReadOnlySpace(*obj));
    i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
    API_RCS_SCOPE(i_isolate, UnboundModuleScript, GetSourceURL);
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    i::Tagged<i::Object> url = i::Cast<i::Script>(obj->script())->source_url();
    return Utils::ToLocal(i::direct_handle(url, i_isolate));
  } else {
    return Local<String>();
  }
}

Local<Value> UnboundModuleScript::GetSourceMappingURL() {
  auto obj = Utils::OpenDirectHandle(this);
  if (i::IsScript(obj->script())) {
    // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is
    // gone.
    DCHECK(!i::HeapLayout::InReadOnlySpace(*obj));
    i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
    API_RCS_SCOPE(i_isolate, UnboundModuleScript, GetSourceMappingURL);
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    i::Tagged<i::Object> url =
        i::Cast<i::Script>(obj->script())->source_mapping_url();
    return Utils::ToLocal(i::direct_handle(url, i_isolate));
  } else {
    return Local<String>();
  }
}

MaybeLocal<Value> Script::Run(Local<Context> context) {
  return Run(context, Local<Data>());
}

MaybeLocal<Value> Script::Run(Local<Context> context,
                              Local<Data> host_defined_options) {
  auto v8_isolate = context->GetIsolate();
  auto i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.Execute");
  ENTER_V8(i_isolate, context, Script, Run, InternalEscapableScope);
  i::TimerEventScope<i::TimerEventExecute> timer_scope(i_isolate);
  i::NestedTimedHistogramScope execute_timer(i_isolate->counters()->execute(),
                                             i_isolate);
  i::AggregatingHistogramTimerScope histogram_timer(
      i_isolate->counters()->compile_lazy());

#if defined(V8_OS_WIN) && defined(V8_ENABLE_ETW_STACK_WALKING)
  // In case ETW has been activated, tasks to log existing code are
  // created. But in case the task runner does not run those before
  // starting to execute code (as it happens in d8, that will run
  // first the code from prompt), then that code will not have
  // JIT instrumentation on time.
  //
  // To avoid this, on running scripts check first if JIT code log is
  // pending and generate immediately.
  if (i::v8_flags.enable_etw_stack_walking) {
    i::ETWJITInterface::MaybeSetHandlerNow(i_isolate);
  }
#endif
  auto fun = i::Cast<i::JSFunction>(Utils::OpenHandle(this));
  i::Handle<i::Object> receiver = i_isolate->global_proxy();
  // TODO(cbruni, chromium:1244145): Remove once migrated to the context.
  i::Handle<i::Object> options(
      i::Cast<i::Script>(fun->shared()->script())->host_defined_options(),
      i_isolate);
  Local<Value> result;
  has_exception = !ToLocal<Value>(
      i::Execution::CallScript(i_isolate, fun, receiver, options), &result);

  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(result);
}

Local<Value> ScriptOrModule::GetResourceName() {
  auto obj = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return ToApiHandle<Value>(i::direct_handle(obj->resource_name(), i_isolate));
}

Local<Data> ScriptOrModule::HostDefinedOptions() {
  auto obj = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*obj);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return ToApiHandle<Data>(
      i::direct_handle(obj->host_defined_options(), i_isolate));
}

Local<UnboundScript> Script::GetUnboundScript() {
  i::DisallowGarbageCollection no_gc;
  auto obj = Utils::OpenDirectHandle(this);
  i::DirectHandle<i::SharedFunctionInfo> sfi(obj->shared(), obj->GetIsolate());
  DCHECK(!i::HeapLayout::InReadOnlySpace(*sfi));
  return ToApiHandle<UnboundScript>(sfi);
}

Local<Value> Script::GetResourceName() {
  i::DisallowGarbageCollection no_gc;
  auto func = Utils::OpenDirectHandle(this);
  i::Tagged<i::SharedFunctionInfo> sfi = func->shared();
  CHECK(IsScript(sfi->script()));
  i::Isolate* i_isolate = func->GetIsolate();
  return ToApiHandle<Value>(
      i::direct_handle(i::Cast<i::Script>(sfi->script())->name(), i_isolate));
}

std::vector<int> Script::GetProducedCompileHints() const {
  i::DisallowGarbageCollection no_gc;
  auto func = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = func->GetIsolate();
  i::Tagged<i::SharedFunctionInfo> sfi = func->shared();
  CHECK(IsScript(sfi->script()));
  i::Tagged<i::Script> script = i::Cast<i::Script>(sfi->script());
  i::Tagged<i::Object> maybe_array_list =
      script->compiled_lazy_function_positions();
  std::vector<int> result;
  if (!IsUndefined(maybe_array_list, i_isolate)) {
    i::Tagged<i::ArrayList> array_list =
        i::Cast<i::ArrayList>(maybe_array_list);
    result.reserve(array_list->length());
    for (int i = 0; i < array_list->length(); ++i) {
      i::Tagged<i::Object> item = array_list->get(i);
      CHECK(IsSmi(item));
      result.push_back(i::Smi::ToInt(item));
    }
  }
  return result;
}

Local<CompileHintsCollector> Script::GetCompileHintsCollector() const {
  i::DisallowGarbageCollection no_gc;
  auto func = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = func->GetIsolate();
  i::Tagged<i::SharedFunctionInfo> sfi = func->shared();
  CHECK(IsScript(sfi->script()));
  i::DirectHandle<i::Script> script(i::Cast<i::Script>(sfi->script()),
                                    i_isolate);
  return ToApiHandle<CompileHintsCollector>(script);
}

std::vector<int> CompileHintsCollector::GetCompileHints(
    Isolate* v8_isolate) const {
  i::DisallowGarbageCollection no_gc;
  auto script = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::Tagged<i::Object> maybe_array_list =
      script->compiled_lazy_function_positions();
  std::vector<int> result;
  if (!IsUndefined(maybe_array_list, i_isolate)) {
    i::Tagged<i::ArrayList> array_list =
        i::Cast<i::ArrayList>(maybe_array_list);
    result.reserve(array_list->length());
    for (int i = 0; i < array_list->length(); ++i) {
      i::Tagged<i::Object> item = array_list->get(i);
      CHECK(IsSmi(item));
      result.push_back(i::Smi::ToInt(item));
    }
  }
  return result;
}

// static
Local<PrimitiveArray> PrimitiveArray::New(Isolate* v8_isolate, int length) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  Utils::ApiCheck(length >= 0, "v8::PrimitiveArray::New",
                  "length must be equal or greater than zero");
  i::DirectHandle<i::FixedArray> array =
      i_isolate->factory()->NewFixedArray(length);
  return ToApiHandle<PrimitiveArray>(array);
}

int PrimitiveArray::Length() const {
  return Utils::OpenDirectHandle(this)->length();
}

void PrimitiveArray::Set(Isolate* v8_isolate, int index,
                         Local<Primitive> item) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto array = Utils::OpenDirectHandle(this);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  Utils::ApiCheck(index >= 0 && index < array->length(),
                  "v8::PrimitiveArray::Set",
                  "index must be greater than or equal to 0 and less than the "
                  "array length");
  array->set(index, *Utils::OpenDirectHandle(*item));
}

Local<Primitive> PrimitiveArray::Get(Isolate* v8_isolate, int index) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto array = Utils::OpenDirectHandle(this);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  Utils::ApiCheck(index >= 0 && index < array->length(),
                  "v8::PrimitiveArray::Get",
                  "index must be greater than or equal to 0 and less than the "
                  "array length");
  return ToApiHandle<Primitive>(i::direct_handle(array->get(index), i_isolate));
}

void v8::PrimitiveArray::CheckCast(v8::Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(
      i::IsFixedArray(*obj), "v8::PrimitiveArray::Cast",
      "Value is not a PrimitiveArray; this is a temporary issue, v8::Data and "
      "v8::PrimitiveArray will not be compatible in the future");
}

int FixedArray::Length() const {
  return Utils::OpenDirectHandle(this)->length();
}

Local<Data> FixedArray::Get(Local<Context> context, int i) const {
  auto self = Utils::OpenDirectHandle(this);
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  CHECK_LT(i, self->length());
  return ToApiHandle<Data>(i::direct_handle(self->get(i), i_isolate));
}

Local<String> ModuleRequest::GetSpecifier() const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  return ToApiHandle<String>(i::direct_handle(self->specifier(), i_isolate));
}

ModuleImportPhase ModuleRequest::GetPhase() const {
  auto self = Utils::OpenDirectHandle(this);
  return self->phase();
}

int ModuleRequest::GetSourceOffset() const {
  return Utils::OpenDirectHandle(this)->position();
}

Local<FixedArray> ModuleRequest::GetImportAttributes() const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  return ToApiHandle<FixedArray>(
      i::direct_handle(self->import_attributes(), i_isolate));
}

Module::Status Module::GetStatus() const {
  auto self = Utils::OpenDirectHandle(this);
  switch (self->status()) {
    case i::Module::kUnlinked:
    case i::Module::kPreLinking:
      return kUninstantiated;
    case i::Module::kLinking:
      return kInstantiating;
    case i::Module::kLinked:
      return kInstantiated;
    case i::Module::kEvaluating:
      return kEvaluating;
    case i::Module::kEvaluatingAsync:
      // TODO(syg): Expose kEvaluatingAsync in API as well.
    case i::Module::kEvaluated:
      return kEvaluated;
    case i::Module::kErrored:
      return kErrored;
  }
  UNREACHABLE();
}

Local<Value> Module::GetException() const {
  Utils::ApiCheck(GetStatus() == kErrored, "v8::Module::GetException",
                  "Module status must be kErrored");
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return ToApiHandle<Value>(i::direct_handle(self->GetException(), i_isolate));
}

Local<FixedArray> Module::GetModuleRequests() const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (i::IsSyntheticModule(*self)) {
    // Synthetic modules are leaf nodes in the module graph. They have no
    // ModuleRequests.
    return ToApiHandle<FixedArray>(
        self->GetReadOnlyRoots().empty_fixed_array_handle());
  } else {
    return ToApiHandle<FixedArray>(i::direct_handle(
        i::Cast<i::SourceTextModule>(self)->info()->module_requests(),
        i_isolate));
  }
}

Location Module::SourceOffsetToLocation(int offset) const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::HandleScope scope(i_isolate);
  Utils::ApiCheck(
      i::IsSourceTextModule(*self), "v8::Module::SourceOffsetToLocation",
      "v8::Module::SourceOffsetToLocation must be used on an SourceTextModule");
  i::DirectHandle<i::Script> script(
      i::Cast<i::SourceTextModule>(self)->GetScript(), i_isolate);
  i::Script::PositionInfo info;
  i::Script::GetPositionInfo(script, offset, &info);
  return v8::Location(info.line, info.column);
}

Local<Value> Module::GetModuleNamespace() {
  Utils::ApiCheck(
      GetStatus() >= kInstantiated, "v8::Module::GetModuleNamespace",
      "v8::Module::GetModuleNamespace must be used on an instantiated module");
  auto self = Utils::OpenHandle(this);
  auto i_isolate = self->GetIsolate();
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::DirectHandle<i::JSModuleNamespace> module_namespace =
      i::Module::GetModuleNamespace(i_isolate, self);
  return ToApiHandle<Value>(module_namespace);
}

Local<UnboundModuleScript> Module::GetUnboundModuleScript() {
  auto self = Utils::OpenDirectHandle(this);
  Utils::ApiCheck(
      i::IsSourceTextModule(*self), "v8::Module::GetUnboundModuleScript",
      "v8::Module::GetUnboundModuleScript must be used on an SourceTextModule");
  auto i_isolate = self->GetIsolate();
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return ToApiHandle<UnboundModuleScript>(i::direct_handle(
      i::Cast<i::SourceTextModule>(self)->GetSharedFunctionInfo(), i_isolate));
}

int Module::ScriptId() const {
  i::Tagged<i::Module> self = *Utils::OpenDirectHandle(this);
  Utils::ApiCheck(i::IsSourceTextModule(self), "v8::Module::ScriptId",
                  "v8::Module::ScriptId must be used on an SourceTextModule");
  DCHECK_NO_SCRIPT_NO_EXCEPTION(self->GetIsolate());
  return i::Cast<i::SourceTextModule>(self)->GetScript()->id();
}

bool Module::HasTopLevelAwait() const {
  i::Tagged<i::Module> self = *Utils::OpenDirectHandle(this);
  if (!i::IsSourceTextModule(self)) return false;
  return i::Cast<i::SourceTextModule>(self)->has_toplevel_await();
}

bool Module::IsGraphAsync() const {
  Utils::ApiCheck(
      GetStatus() >= kInstantiated, "v8::Module::IsGraphAsync",
      "v8::Module::IsGraphAsync must be used on an instantiated module");
  i::Tagged<i::Module> self = *Utils::OpenDirectHandle(this);
  auto i_isolate = self->GetIsolate();
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return self->IsGraphAsync(i_isolate);
}

bool Module::IsSourceTextModule() const {
  auto self = Utils::OpenDirectHandle(this);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(self->GetIsolate());
  return i::IsSourceTextModule(*self);
}

bool Module::IsSyntheticModule() const {
  auto self = Utils::OpenDirectHandle(this);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(self->GetIsolate());
  return i::IsSyntheticModule(*self);
}

int Module::GetIdentityHash() const {
  auto self = Utils::OpenDirectHandle(this);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(self->GetIsolate());
  return self->hash();
}

Maybe<bool> Module::InstantiateModule(Local<Context> context,
                                      ResolveModuleCallback module_callback,
                                      ResolveSourceCallback source_callback) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Module, InstantiateModule, i::HandleScope);
  has_exception =
      !i::Module::Instantiate(i_isolate, Utils::OpenHandle(this), context,
                              module_callback, source_callback);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(true);
}

MaybeLocal<Value> Module::Evaluate(Local<Context> context) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.Execute");
  ENTER_V8(i_isolate, context, Module, Evaluate, InternalEscapableScope);
  i::TimerEventScope<i::TimerEventExecute> timer_scope(i_isolate);
  i::NestedTimedHistogramScope execute_timer(i_isolate->counters()->execute(),
                                             i_isolate);
  i::AggregatingHistogramTimerScope timer(
      i_isolate->counters()->compile_lazy());

  auto self = Utils::OpenHandle(this);
  Utils::ApiCheck(self->status() >= i::Module::kLinked, "Module::Evaluate",
                  "Expected instantiated module");

  Local<Value> result;
  has_exception = !ToLocal(i::Module::Evaluate(i_isolate, self), &result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(result);
}

Local<Module> Module::CreateSyntheticModule(
    Isolate* v8_isolate, Local<String> module_name,
    const MemorySpan<const Local<String>>& export_names,
    v8::Module::SyntheticModuleEvaluationSteps evaluation_steps) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto i_module_name = Utils::OpenHandle(*module_name);
  i::DirectHandle<i::FixedArray> i_export_names =
      i_isolate->factory()->NewFixedArray(
          static_cast<int>(export_names.size()));
  for (int i = 0; i < i_export_names->length(); ++i) {
    i::DirectHandle<i::String> str = i_isolate->factory()->InternalizeString(
        Utils::OpenDirectHandle(*export_names[i]));
    i_export_names->set(i, *str);
  }
  return v8::Utils::ToLocal(
      i::Handle<i::Module>(i_isolate->factory()->NewSyntheticModule(
          i_module_name, i_export_names, evaluation_steps)));
}

Maybe<bool> Module::SetSyntheticModuleExport(Isolate* v8_isolate,
                                             Local<String> export_name,
                                             Local<v8::Value> export_value) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto i_export_name = Utils::OpenHandle(*export_name);
  auto i_export_value = Utils::OpenHandle(*export_value);
  auto self = Utils::OpenHandle(this);
  Utils::ApiCheck(i::IsSyntheticModule(*self),
                  "v8::Module::SyntheticModuleSetExport",
                  "v8::Module::SyntheticModuleSetExport must only be called on "
                  "a SyntheticModule");
  ENTER_V8_NO_SCRIPT(i_isolate, v8_isolate->GetCurrentContext(), Module,
                     SetSyntheticModuleExport, i::HandleScope);
  has_exception = i::SyntheticModule::SetExport(
                      i_isolate, i::Cast<i::SyntheticModule>(self),
                      i_export_name, i_export_value)
                      .IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(true);
}

std::pair<LocalVector<Module>, LocalVector<Message>>
Module::GetStalledTopLevelAwaitMessages(Isolate* isolate) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  auto self = Utils::OpenDirectHandle(this);
  Utils::ApiCheck(i::IsSourceTextModule(*self),
                  "v8::Module::GetStalledTopLevelAwaitMessages",
                  "v8::Module::GetStalledTopLevelAwaitMessages must only be "
                  "called on a SourceTextModule");
  std::vector<
      std::tuple<i::Handle<i::SourceTextModule>, i::Handle<i::JSMessageObject>>>
      stalled_awaits =
          i::Cast<i::SourceTextModule>(self)->GetStalledTopLevelAwaitMessages(
              i_isolate);

  LocalVector<Module> modules(isolate);
  LocalVector<Message> messages(isolate);

  if (size_t stalled_awaits_count = stalled_awaits.size();
      stalled_awaits_count > 0) {
    modules.reserve(stalled_awaits_count);
    messages.reserve(stalled_awaits_count);
    for (auto [module, message] : stalled_awaits) {
      modules.push_back(ToApiHandle<Module>(module));
      messages.push_back(ToApiHandle<Message>(message));
    }
  }

  return {modules, messages};
}

namespace {

i::ScriptDetails GetScriptDetails(
    i::Isolate* i_isolate, Local<Value> resource_name, int resource_line_offset,
    int resource_column_offset, Local<Value> source_map_url,
    Local<Data> host_defined_options, ScriptOriginOptions origin_options) {
  i::ScriptDetails script_details(Utils::OpenHandle(*(resource_name), true),
                                  origin_options);
  script_details.line_offset = resource_line_offset;
  script_details.column_offset = resource_column_offset;
  script_details.host_defined_options =
      host_defined_options.IsEmpty()
          ? i_isolate->factory()->empty_fixed_array()
          : Utils::OpenHandle(*(host_defined_options));
  if (!source_map_url.IsEmpty()) {
    script_details.source_map_url = Utils::OpenHandle(*(source_map_url));
  }
  return script_details;
}

}  // namespace

MaybeLocal<UnboundScript> ScriptCompiler::CompileUnboundInternal(
    Isolate* v8_isolate, Source* source, CompileOptions options,
    NoCacheReason no_cache_reason) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.ScriptCompiler");
  ENTER_V8_NO_SCRIPT(i_isolate, v8_isolate->GetCurrentContext(), ScriptCompiler,
                     CompileUnbound, InternalEscapableScope);

  auto str = Utils::OpenHandle(*(source->source_string));

  i::DirectHandle<i::SharedFunctionInfo> result;
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"), "V8.CompileScript");
  i::ScriptDetails script_details = GetScriptDetails(
      i_isolate, source->resource_name, source->resource_line_offset,
      source->resource_column_offset, source->source_map_url,
      source->host_defined_options, source->resource_options);

  i::MaybeDirectHandle<i::SharedFunctionInfo> maybe_function_info;
  if (options & kConsumeCodeCache) {
    if (source->consume_cache_task) {
      // Take ownership of the internal deserialization task and clear it off
      // the consume task on the source.
      DCHECK_NOT_NULL(source->consume_cache_task->impl_);
      std::unique_ptr<i::BackgroundDeserializeTask> deserialize_task =
          std::move(source->consume_cache_task->impl_);
      maybe_function_info =
          i::Compiler::GetSharedFunctionInfoForScriptWithDeserializeTask(
              i_isolate, str, script_details, deserialize_task.get(), options,
              no_cache_reason, i::NOT_NATIVES_CODE,
              &source->compilation_details);
      source->cached_data->rejected = deserialize_task->rejected();
    } else {
      DCHECK(source->cached_data);
      // AlignedCachedData takes care of pointer-aligning the data.
      auto cached_data = std::make_unique<i::AlignedCachedData>(
          source->cached_data->data, source->cached_data->length);
      maybe_function_info =
          i::Compiler::GetSharedFunctionInfoForScriptWithCachedData(
              i_isolate, str, script_details, cached_data.get(), options,
              no_cache_reason, i::NOT_NATIVES_CODE,
              &source->compilation_details);
      source->cached_data->rejected = cached_data->rejected();
    }
  } else if (options & kConsumeCompileHints) {
    maybe_function_info =
        i::Compiler::GetSharedFunctionInfoForScriptWithCompileHints(
            i_isolate, str, script_details, source->compile_hint_callback,
            source->compile_hint_callback_data, options, no_cache_reason,
            i::NOT_NATIVES_CODE, &source->compilation_details);
  } else {
    // Compile without any cache.
    maybe_function_info = i::Compiler::GetSharedFunctionInfoForScript(
        i_isolate, str, script_details, options, no_cache_reason,
        i::NOT_NATIVES_CODE, &source->compilation_details);
  }

  has_exception = !maybe_function_info.ToHandle(&result);
  DCHECK_IMPLIES(!has_exception, !i::HeapLayout::InReadOnlySpace(*result));
  RETURN_ON_FAILED_EXECUTION(UnboundScript);
  RETURN_ESCAPED(ToApiHandle<UnboundScript>(result));
}

MaybeLocal<UnboundScript> ScriptCompiler::CompileUnboundScript(
    Isolate* v8_isolate, Source* source, CompileOptions options,
    NoCacheReason no_cache_reason) {
  Utils::ApiCheck(
      !source->GetResourceOptions().IsModule(),
      "v8::ScriptCompiler::CompileUnboundScript",
      "v8::ScriptCompiler::CompileModule must be used to compile modules");
  return CompileUnboundInternal(v8_isolate, source, options, no_cache_reason);
}

MaybeLocal<Script> ScriptCompiler::Compile(Local<Context> context,
                                           Source* source,
                                           CompileOptions options,
                                           NoCacheReason no_cache_reason) {
  Utils::ApiCheck(
      !source->GetResourceOptions().IsModule(), "v8::ScriptCompiler::Compile",
      "v8::ScriptCompiler::CompileModule must be used to compile modules");
  auto i_isolate = context->GetIsolate();
  MaybeLocal<UnboundScript> maybe =
      CompileUnboundInternal(i_isolate, source, options, no_cache_reason);
  Local<UnboundScript> result;
  if (!maybe.ToLocal(&result)) return MaybeLocal<Script>();
  v8::Context::Scope scope(context);
  return result->BindToCurrentContext();
}

MaybeLocal<Module> ScriptCompiler::CompileModule(
    Isolate* v8_isolate, Source* source, CompileOptions options,
    NoCacheReason no_cache_reason) {
  Utils::ApiCheck(v8::ScriptCompiler::CompileOptionsIsValid(options),
                  "v8::ScriptCompiler::CompileModule",
                  "Invalid CompileOptions");
  Utils::ApiCheck(source->GetResourceOptions().IsModule(),
                  "v8::ScriptCompiler::CompileModule",
                  "Invalid ScriptOrigin: is_module must be true");
  MaybeLocal<UnboundScript> maybe =
      CompileUnboundInternal(v8_isolate, source, options, no_cache_reason);
  Local<UnboundScript> unbound;
  if (!maybe.ToLocal(&unbound)) return MaybeLocal<Module>();
  auto shared = Utils::OpenHandle(*unbound);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  return ToApiHandle<Module>(i_isolate->factory()->NewSourceTextModule(shared));
}

// static
V8_WARN_UNUSED_RESULT MaybeLocal<Function> ScriptCompiler::CompileFunction(
    Local<Context> v8_context, Source* source, size_t arguments_count,
    Local<String> arguments[], size_t context_extension_count,
    Local<Object> context_extensions[], CompileOptions options,
    NoCacheReason no_cache_reason) {
  PREPARE_FOR_EXECUTION(v8_context, ScriptCompiler, CompileFunction);
  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.ScriptCompiler");

  DCHECK(options == CompileOptions::kConsumeCodeCache ||
         options == CompileOptions::kEagerCompile ||
         options == CompileOptions::kNoCompileOptions);

  i::Handle<i::Context> context = Utils::OpenHandle(*v8_context);

  DCHECK(IsNativeContext(*context));

  i::Handle<i::FixedArray> arguments_list =
      i_isolate->factory()->NewFixedArray(static_cast<int>(arguments_count));
  for (int i = 0; i < static_cast<int>(arguments_count); i++) {
    auto argument = Utils::OpenHandle(*arguments[i]);
    if (!i::String::IsIdentifier(i_isolate, argument)) return Local<Function>();
    arguments_list->set(i, *argument);
  }

  for (size_t i = 0; i < context_extension_count; ++i) {
    i::DirectHandle<i::JSReceiver> extension =
        Utils::OpenDirectHandle(*context_extensions[i]);
    if (!IsJSObject(*extension)) return Local<Function>();
    context = i_isolate->factory()->NewWithContext(
        context,
        i::ScopeInfo::CreateForWithScope(
            i_isolate,
            IsNativeContext(*context)
                ? i::Handle<i::ScopeInfo>::null()
                : i::Handle<i::ScopeInfo>(context->scope_info(), i_isolate)),
        extension);
  }

  i::ScriptDetails script_details = GetScriptDetails(
      i_isolate, source->resource_name, source->resource_line_offset,
      source->resource_column_offset, source->source_map_url,
      source->host_defined_options, source->resource_options);
  script_details.wrapped_arguments = arguments_list;

  std::unique_ptr<i::AlignedCachedData> cached_data;
  if (options & kConsumeCodeCache) {
    DCHECK(source->cached_data);
    // ScriptData takes care of pointer-aligning the data.
    cached_data.reset(new i::AlignedCachedData(source->cached_data->data,
                                               source->cached_data->length));
  }

  i::Handle<i::JSFunction> result;
  has_exception =
      !i::Compiler::GetWrappedFunction(
           Utils::OpenHandle(*source->source_string), context, script_details,
           cached_data.get(), options, no_cache_reason)
           .ToHandle(&result);
  if (options & kConsumeCodeCache) {
    source->cached_data->rejected = cached_data->rejected();
  }
  RETURN_ON_FAILED_EXECUTION(Function);
  return handle_scope.Escape(Utils::CallableToLocal(result));
}

void ScriptCompiler::ScriptStreamingTask::Run() { data_->task->Run(); }

ScriptCompiler::ScriptStreamingTask* ScriptCompiler::StartStreaming(
    Isolate* v8_isolate, StreamedSource* source, v8::ScriptType type,
    CompileOptions options, CompileHintCallback compile_hint_callback,
    void* compile_hint_callback_data) {
  Utils::ApiCheck(v8::ScriptCompiler::CompileOptionsIsValid(options),
                  "v8::ScriptCompiler::StartStreaming",
                  "Invalid CompileOptions");
  if (!i::v8_flags.script_streaming) return nullptr;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::ScriptStreamingData* data = source->impl();
  std::unique_ptr<i::BackgroundCompileTask> task =
      std::make_unique<i::BackgroundCompileTask>(
          data, i_isolate, type, options, &source->compilation_details(),
          compile_hint_callback, compile_hint_callback_data);
  data->task = std::move(task);
  return new ScriptCompiler::ScriptStreamingTask(data);
}

ScriptCompiler::ConsumeCodeCacheTask::ConsumeCodeCacheTask(
    std::unique_ptr<i::BackgroundDeserializeTask> impl)
    : impl_(std::move(impl)) {}

ScriptCompiler::ConsumeCodeCacheTask::~ConsumeCodeCacheTask() = default;

void ScriptCompiler::ConsumeCodeCacheTask::Run() { impl_->Run(); }

void ScriptCompiler::ConsumeCodeCacheTask::SourceTextAvailable(
    Isolate* v8_isolate, Local<String> source_text,
    const ScriptOrigin& origin) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto str = Utils::OpenHandle(*source_text);
  i::ScriptDetails script_details =
      GetScriptDetails(i_isolate, origin.ResourceName(), origin.LineOffset(),
                       origin.ColumnOffset(), origin.SourceMapUrl(),
                       origin.GetHostDefinedOptions(), origin.Options());
  impl_->SourceTextAvailable(i_isolate, str, script_details);
}

bool ScriptCompiler::ConsumeCodeCacheTask::ShouldMergeWithExistingScript()
    const {
  if (!i::v8_flags
           .merge_background_deserialized_script_with_compilation_cache) {
    return false;
  }
  return impl_->ShouldMergeWithExistingScript();
}

void ScriptCompiler::ConsumeCodeCacheTask::MergeWithExistingScript() {
  DCHECK(
      i::v8_flags.merge_background_deserialized_script_with_compilation_cache);
  impl_->MergeWithExistingScript();
}

ScriptCompiler::ConsumeCodeCacheTask* ScriptCompiler::StartConsumingCodeCache(
    Isolate* v8_isolate, std::unique_ptr<CachedData> cached_data) {
  if (!i::v8_flags.concurrent_cache_deserialization) return nullptr;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return new ScriptCompiler::ConsumeCodeCacheTask(
      std::make_unique<i::BackgroundDeserializeTask>(i_isolate,
                                                     std::move(cached_data)));
}

ScriptCompiler::ConsumeCodeCacheTask*
ScriptCompiler::StartConsumingCodeCacheOnBackground(
    Isolate* v8_isolate, std::unique_ptr<CachedData> cached_data) {
  if (!i::v8_flags.concurrent_cache_deserialization) return nullptr;
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  return new ScriptCompiler::ConsumeCodeCacheTask(
      std::make_unique<i::BackgroundDeserializeTask>(i_isolate,
                                                     std::move(cached_data)));
}

namespace {
i::MaybeDirectHandle<i::SharedFunctionInfo> CompileStreamedSource(
    i::Isolate* i_isolate, ScriptCompiler::StreamedSource* v8_source,
    Local<String> full_source_string, const ScriptOrigin& origin) {
  auto str = Utils::OpenHandle(*full_source_string);
  i::ScriptDetails script_details =
      GetScriptDetails(i_isolate, origin.ResourceName(), origin.LineOffset(),
                       origin.ColumnOffset(), origin.SourceMapUrl(),
                       origin.GetHostDefinedOptions(), origin.Options());
  i::ScriptStreamingData* data = v8_source->impl();
  return i::Compiler::GetSharedFunctionInfoForStreamedScript(
      i_isolate, str, script_details, data, &v8_source->compilation_details());
}

}  // namespace

MaybeLocal<Script> ScriptCompiler::Compile(Local<Context> context,
                                           StreamedSource* v8_source,
                                           Local<String> full_source_string,
                                           const ScriptOrigin& origin) {
  PREPARE_FOR_EXECUTION(context, ScriptCompiler, Compile);
  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.ScriptCompiler");
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "V8.CompileStreamedScript");
  i::DirectHandle<i::SharedFunctionInfo> sfi;
  i::MaybeDirectHandle<i::SharedFunctionInfo> maybe_sfi =
      CompileStreamedSource(i_isolate, v8_source, full_source_string, origin);
  has_exception = !maybe_sfi.ToHandle(&sfi);
  if (has_exception) i_isolate->ReportPendingMessages();
  RETURN_ON_FAILED_EXECUTION(Script);
  Local<UnboundScript> generic = ToApiHandle<UnboundScript>(sfi);
  if (generic.IsEmpty()) return Local<Script>();
  Local<Script> bound = generic->BindToCurrentContext();
  if (bound.IsEmpty()) return Local<Script>();
  RETURN_ESCAPED(bound);
}

MaybeLocal<Module> ScriptCompiler::CompileModule(
    Local<Context> context, StreamedSource* v8_source,
    Local<String> full_source_string, const ScriptOrigin& origin) {
  PREPARE_FOR_EXECUTION(context, ScriptCompiler, Compile);
  TRACE_EVENT_CALL_STATS_SCOPED(i_isolate, "v8", "V8.ScriptCompiler");
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "V8.CompileStreamedModule");
  i::DirectHandle<i::SharedFunctionInfo> sfi;
  i::MaybeDirectHandle<i::SharedFunctionInfo> maybe_sfi =
      CompileStreamedSource(i_isolate, v8_source, full_source_string, origin);
  has_exception = !maybe_sfi.ToHandle(&sfi);
  if (has_exception) i_isolate->ReportPendingMessages();
  RETURN_ON_FAILED_EXECUTION(Module);
  RETURN_ESCAPED(
      ToApiHandle<Module>(i_isolate->factory()->NewSourceTextModule(sfi)));
}

uint32_t ScriptCompiler::CachedDataVersionTag() {
  return static_cast<uint32_t>(base::hash_combine(
      internal::Version::Hash(), internal::FlagList::Hash(),
      static_cast<uint32_t>(internal::CpuFeatures::SupportedFeatures())));
}

ScriptCompiler::CachedData* ScriptCompiler::CreateCodeCache(
    Local<UnboundScript> unbound_script) {
  auto shared = Utils::OpenHandle(*unbound_script);
  // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is gone.
  DCHECK(!i::HeapLayout::InReadOnlySpace(*shared));
  i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*shared);
  Utils::ApiCheck(!i_isolate->serializer_enabled(),
                  "ScriptCompiler::CreateCodeCache",
                  "Cannot create code cache while creating a snapshot");
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  DCHECK(shared->is_toplevel());
  return i::CodeSerializer::Serialize(i_isolate, shared);
}

// static
ScriptCompiler::CachedData* ScriptCompiler::CreateCodeCache(
    Local<UnboundModuleScript> unbound_module_script) {
  i::Handle<i::SharedFunctionInfo> shared =
      Utils::OpenHandle(*unbound_module_script);
  // TODO(jgruber): Remove this DCHECK once Function::GetUnboundScript is gone.
  DCHECK(!i::HeapLayout::InReadOnlySpace(*shared));
  i::Isolate* i_isolate = i::GetIsolateFromWritableObject(*shared);
  Utils::ApiCheck(!i_isolate->serializer_enabled(),
                  "ScriptCompiler::CreateCodeCache",
                  "Cannot create code cache while creating a snapshot");
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  DCHECK(shared->is_toplevel());
  return i::CodeSerializer::Serialize(i_isolate, shared);
}

ScriptCompiler::CachedData* ScriptCompiler::CreateCodeCacheForFunction(
    Local<Function> function) {
  auto js_function = i::Cast<i::JSFunction>(Utils::OpenDirectHandle(*function));
  i::Isolate* i_isolate = js_function->GetIsolate();
  Utils::ApiCheck(!i_isolate->serializer_enabled(),
                  "ScriptCompiler::CreateCodeCacheForFunction",
                  "Cannot create code cache while creating a snapshot");
  i::Handle<i::SharedFunctionInfo> shared(js_function->shared(), i_isolate);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  Utils::ApiCheck(shared->is_wrapped(),
                  "v8::ScriptCompiler::CreateCodeCacheForFunction",
                  "Expected SharedFunctionInfo with wrapped source code");
  return i::CodeSerializer::Serialize(i_isolate, shared);
}

MaybeLocal<Script> Script::Compile(Local<Context> context, Local<String> source,
                                   ScriptOrigin* origin) {
  if (origin) {
    ScriptCompiler::Source script_source(source, *origin);
    return ScriptCompiler::Compile(context, &script_source);
  }
  ScriptCompiler::Source script_source(source);
  return ScriptCompiler::Compile(context, &script_source);
}

// --- E x c e p t i o n s ---

v8::TryCatch::TryCatch(v8::Isolate* v8_isolate)
    : i_isolate_(reinterpret_cast<i::Isolate*>(v8_isolate)),
      next_(i_isolate_->try_catch_handler()),
      is_verbose_(false),
      can_continue_(true),
      capture_message_(true),
      rethrow_(false) {
  ResetInternal();
  // Special handling for simulators which have a separate JS stack.
  js_stack_comparable_address_ = static_cast<internal::Address>(
      i::SimulatorStack::RegisterJSStackComparableAddress(i_isolate_));
  i_isolate_->RegisterTryCatchHandler(this);
}

namespace {

i::Tagged<i::Object> ToObject(void* object) {
  return i::Tagged<i::Object>(reinterpret_cast<i::Address>(object));
}

}  // namespace

v8::TryCatch::~TryCatch() {
  if (HasCaught()) {
    if (rethrow_ || (V8_UNLIKELY(HasTerminated()) &&
                     !i_isolate_->thread_local_top()->CallDepthIsZero())) {
      if (capture_message_) {
        // If an exception was caught and rethrow_ is indicated, the saved
        // message, script, and location need to be restored to Isolate TLS
        // for reuse.  capture_message_ needs to be disabled so that Throw()
        // does not create a new message.
        i_isolate_->thread_local_top()->rethrowing_message_ = true;
        i_isolate_->set_pending_message(ToObject(message_obj_));
      }
      i_isolate_->UnregisterTryCatchHandler(this);
      i_isolate_->clear_internal_exception();
      i_isolate_->Throw(ToObject(exception_));
      return;
    }
    Reset();
  }
  i_isolate_->UnregisterTryCatchHandler(this);
  DCHECK_IMPLIES(rethrow_,
                 !i_isolate_->thread_local_top()->rethrowing_message_);
}

void* v8::TryCatch::operator new(size_t) { base::OS::Abort(); }
void* v8::TryCatch::operator new[](size_t) { base::OS::Abort(); }
void v8::TryCatch::operator delete(void*, size_t) { base::OS::Abort(); }
void v8::TryCatch::operator delete[](void*, size_t) { base::OS::Abort(); }

bool v8::TryCatch::HasCaught() const {
  return !IsTheHole(ToObject(exception_), i_isolate_);
}

bool v8::TryCatch::CanContinue() const { return can_continue_; }

bool v8::TryCatch::HasTerminated() const {
  return ToObject(exception_) ==
         i::ReadOnlyRoots(i_isolate_).termination_exception();
}

v8::Local<v8::Value> v8::TryCatch::ReThrow() {
  if (!HasCaught()) return v8::Local<v8::Value>();
  rethrow_ = true;
  return v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate_));
}

v8::Local<Value> v8::TryCatch::Exception() const {
  if (!HasCaught()) return v8::Local<Value>();
  if (HasTerminated()) {
    return v8::Utils::ToLocal(i::ReadOnlyRoots(i_isolate_).null_value_handle());
  }
  return v8::Utils::ToLocal(i::handle(ToObject(exception_), i_isolate_));
}

MaybeLocal<Value> v8::TryCatch::StackTrace(Local<Context> context,
                                           Local<Value> exception) {
  auto i_exception = Utils::OpenHandle(*exception);
  if (!IsJSObject(*i_exception)) return v8::Local<Value>();
  PREPARE_FOR_EXECUTION(context, TryCatch, StackTrace);
  auto obj = i::Cast<i::JSObject>(i_exception);
  i::Handle<i::String> name = i_isolate->factory()->stack_string();
  Maybe<bool> maybe = i::JSReceiver::HasProperty(i_isolate, obj, name);
  has_exception = maybe.IsNothing();
  RETURN_ON_FAILED_EXECUTION(Value);
  if (!maybe.FromJust()) return v8::Local<Value>();
  Local<Value> result;
  has_exception = !ToLocal<Value>(
      i::JSReceiver::GetProperty(i_isolate, obj, name), &result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(result);
}

MaybeLocal<Value> v8::TryCatch::StackTrace(Local<Context> context) const {
  if (!HasCaught()) return v8::Local<Value>();
  return StackTrace(context, Exception());
}

v8::Local<v8::Message> v8::TryCatch::Message() const {
  i::Tagged<i::Object> message = ToObject(message_obj_);
  DCHECK(IsJSMessageObject(message) || IsTheHole(message, i_isolate_));
  if (HasCaught() && !IsTheHole(message, i_isolate_)) {
    return v8::Utils::MessageToLocal(i::Handle<i::Object>(message, i_isolate_));
  } else {
    return v8::Local<v8::Message>();
  }
}

void v8::TryCatch::Reset() {
  if (rethrow_) return;
  if (V8_UNLIKELY(i_isolate_->is_execution_terminating()) &&
      !i_isolate_->thread_local_top()->CallDepthIsZero()) {
    return;
  }
  i_isolate_->clear_internal_exception();
  i_isolate_->clear_pending_message();
  ResetInternal();
}

void v8::TryCatch::ResetInternal() {
  i::Tagged<i::Object> the_hole = i::ReadOnlyRoots(i_isolate_).the_hole_value();
  exception_ = reinterpret_cast<void*>(the_hole.ptr());
  message_obj_ = reinterpret_cast<void*>(the_hole.ptr());
}

void v8::TryCatch::SetVerbose(bool value) { is_verbose_ = value; }

bool v8::TryCatch::IsVerbose() const { return is_verbose_; }

void v8::TryCatch::SetCaptureMessage(bool value) { capture_message_ = value; }

// --- M e s s a g e ---

Local<String> Message::Get() const {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  InternalEscapableScope scope(i_isolate);
  i::Handle<i::String> raw_result =
      i::MessageHandler::GetMessage(i_isolate, self);
  Local<String> result = Utils::ToLocal(raw_result);
  return scope.Escape(result);
}

v8::Isolate* Message::GetIsolate() const {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  return reinterpret_cast<Isolate*>(i_isolate);
}

ScriptOrigin Message::GetScriptOrigin() const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::DirectHandle<i::Script> script(self->script(), i_isolate);
  return GetScriptOriginForScript(i_isolate, script);
}

void ScriptOrigin::VerifyHostDefinedOptions() const {
  // TODO(cbruni, chromium:1244145): Remove checks once we allow arbitrary
  // host-defined options.
  if (host_defined_options_.IsEmpty()) return;
  Utils::ApiCheck(host_defined_options_->IsFixedArray(), "ScriptOrigin()",
                  "Host-defined options has to be a PrimitiveArray");
  auto options =
      Utils::OpenDirectHandle(*host_defined_options_.As<FixedArray>());
  for (int i = 0; i < options->length(); i++) {
    Utils::ApiCheck(i::IsPrimitive(options->get(i)), "ScriptOrigin()",
                    "PrimitiveArray can only contain primtive values");
  }
}

v8::Local<Value> Message::GetScriptResourceName() const {
  DCHECK_NO_SCRIPT_NO_EXCEPTION(Utils::OpenDirectHandle(this)->GetIsolate());
  return GetScriptOrigin().ResourceName();
}

v8::Local<v8::StackTrace> Message::GetStackTrace() const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  InternalEscapableScope scope(i_isolate);
  i::Handle<i::Object> stack_trace(self->stack_trace(), i_isolate);
  if (!IsStackTraceInfo(*stack_trace)) return {};
  return scope.Escape(
      Utils::StackTraceToLocal(i::Cast<i::StackTraceInfo>(stack_trace)));
}

Maybe<int> Message::GetLineNumber(Local<Context> context) const {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  HandleScope handle_scope(reinterpret_cast<Isolate*>(i_isolate));
  i::JSMessageObject::EnsureSourcePositionsAvailable(i_isolate, self);
  return Just(self->GetLineNumber());
}

int Message::GetStartPosition() const {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  HandleScope handle_scope(reinterpret_cast<Isolate*>(i_isolate));
  i::JSMessageObject::EnsureSourcePositionsAvailable(i_isolate, self);
  return self->GetStartPosition();
}

int Message::GetEndPosition() const {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  HandleScope handle_scope(reinterpret_cast<Isolate*>(i_isolate));
  i::JSMessageObject::EnsureSourcePositionsAvailable(i_isolate, self);
  return self->GetEndPosition();
}

int Message::ErrorLevel() const {
  auto self = Utils::OpenDirectHandle(this);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(self->GetIsolate());
  return self->error_level();
}

int Message::GetStartColumn() const {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  HandleScope handle_scope(reinterpret_cast<Isolate*>(i_isolate));
  i::JSMessageObject::EnsureSourcePositionsAvailable(i_isolate, self);
  return self->GetColumnNumber();
}

int Message::GetWasmFunctionIndex() const {
#if V8_ENABLE_WEBASSEMBLY
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  HandleScope handle_scope(reinterpret_cast<Isolate*>(i_isolate));
  i::JSMessageObject::EnsureSourcePositionsAvailable(i_isolate, self);
  int start_position = self->GetColumnNumber();
  if (start_position == -1) return Message::kNoWasmFunctionIndexInfo;

  i::DirectHandle<i::Script> script(self->script(), i_isolate);

  if (script->type() != i::Script::Type::kWasm) {
    return Message::kNoWasmFunctionIndexInfo;
  }

  auto debug_script = ToApiHandle<debug::Script>(script);
  return Local<debug::WasmScript>::Cast(debug_script)
      ->GetContainingFunction(start_position);
#else
  return Message::kNoWasmFunctionIndexInfo;
#endif  // V8_ENABLE_WEBASSEMBLY
}

Maybe<int> Message::GetStartColumn(Local<Context> context) const {
  return Just(GetStartColumn());
}

int Message::GetEndColumn() const {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  HandleScope handle_scope(reinterpret_cast<Isolate*>(i_isolate));
  i::JSMessageObject::EnsureSourcePositionsAvailable(i_isolate, self);
  const int column_number = self->GetColumnNumber();
  if (column_number == -1) return -1;
  const int start = self->GetStartPosition();
  const int end = self->GetEndPosition();
  return column_number + (end - start);
}

Maybe<int> Message::GetEndColumn(Local<Context> context) const {
  return Just(GetEndColumn());
}

bool Message::IsSharedCrossOrigin() const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return self->script()->origin_options().IsSharedCrossOrigin();
}

bool Message::IsOpaque() const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return self->script()->origin_options().IsOpaque();
}

MaybeLocal<String> Message::GetSource(Local<Context> context) const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  InternalEscapableScope handle_scope(i_isolate);
"""


```