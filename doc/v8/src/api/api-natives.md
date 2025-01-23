Response: The user wants to understand the functionality of the C++ file `api-natives.cc` within the V8 JavaScript engine. I need to analyze the code and provide a summary of its purpose. Since the file name contains "api" and "natives", it's likely related to how JavaScript interacts with native C++ code. Key things to look for are:

1. **Core Responsibilities:** What are the main tasks performed by the code?  Instantiation of objects and functions based on templates seems to be a central theme.
2. **Interaction with JavaScript:** How does this C++ code relate to JavaScript concepts? Look for terms like `JSObject`, `JSFunction`, `prototype`, `constructor`, and how they are created and manipulated.
3. **Use of Templates:** The frequent use of `TemplateInfo` suggests a mechanism for defining object and function structures in C++ that are then used to create corresponding JavaScript objects and functions.
4. **Caching:** The code mentions caching, likely to optimize the creation of objects and functions.
5. **Access Checks:** The presence of `AccessCheckDisableScope` and related functions hints at security or access control mechanisms.
6. **Property Handling:**  Functions like `DefineDataProperty`, `DefineAccessorProperty`, and `AddPropertyToPropertyList` point towards the management of properties on JavaScript objects.

After analyzing these aspects, I should be able to formulate a concise summary and provide relevant JavaScript examples to illustrate the connection between the C++ code and JavaScript behavior.

**Mental Sandbox:**

* **Instantiation Process:** The code seems to handle the process of creating JavaScript objects and functions from C++ template definitions. This likely involves setting up the object's prototype, properties, and potentially accessors.
* **Template as Blueprint:**  `ObjectTemplateInfo` and `FunctionTemplateInfo` appear to act as blueprints or specifications defined in C++ that dictate the structure and behavior of JavaScript objects and functions.
* **Caching for Performance:** Caching instantiated objects and functions can significantly speed up repeated creation.
* **Access Control:** The access check mechanisms probably ensure that JavaScript code interacting with native objects adheres to certain restrictions.
* **Property Definition:**  The property-related functions demonstrate how properties (data and accessors) defined in C++ templates are applied to JavaScript objects.

**Example Scenario:** Imagine a C++ API exposing a native object to JavaScript. This file likely plays a role in creating the JavaScript representation of that native object, including its properties and methods (functions).

**Constraint Checklist & Confidence Score:**

1. Summarize the functionality: Yes, I can do this.
2. Explain relationship with JavaScript: Yes, this is a key aspect.
3. Provide JavaScript examples: Yes, I will formulate illustrative examples.

Confidence Score: 5/5

Strategizing complete. I will now proceed with generating the response.
这个C++源代码文件 `api-natives.cc` 的主要功能是**实现 V8 引擎中将 C++ 定义的模板（templates）实例化为 JavaScript 对象和函数的核心逻辑**。它负责连接 C++ 的模板定义和 JavaScript 的运行时对象创建。

更具体地说，这个文件处理以下关键任务：

1. **实例化对象（InstantiateObject）：**  根据 `ObjectTemplateInfo` 中定义的模板信息创建 JavaScript 对象。这包括设置对象的原型、属性（包括数据属性和访问器属性），以及处理继承自父模板的属性。它还涉及到缓存机制，以优化重复实例化相同模板的性能。

2. **实例化函数（InstantiateFunction）：** 根据 `FunctionTemplateInfo` 中定义的模板信息创建 JavaScript 函数。这包括设置函数的原型、关联的 C++ 回调函数、以及处理函数的属性。 同样也包括缓存机制。

3. **定义属性（DefineDataProperty, DefineAccessorProperty）：**  在 JavaScript 对象上定义数据属性和访问器属性。这些属性的信息通常来源于模板定义。

4. **处理访问检查（DisableAccessChecks, EnableAccessChecks）：**  在实例化过程中临时禁用或启用访问检查，以允许在对象创建时进行特定的操作，而不会触发访问限制。

5. **处理内置对象（GetIntrinsic）：** 获取 V8 引擎内置的 JavaScript 对象，例如 `Array.prototype` 或 `Object.prototype`。

6. **配置实例（ConfigureInstance）：** 在对象或函数实例化后，根据模板信息进一步配置实例，例如添加属性和访问器。

7. **创建 API 函数（CreateApiFunction）：**  创建一个与 C++ 函数关联的 JavaScript 函数对象。

**它与 JavaScript 功能的关系非常密切。**  V8 引擎允许开发者通过 C++ API (通常在 `v8::` 命名空间下) 定义一些在 JavaScript 中可用的对象和函数。`api-natives.cc` 中的代码就是实现这种能力的关键部分。

**JavaScript 举例说明：**

假设你在 C++ 中定义了一个名为 `MyObject` 的模板，它有一个名为 `myProperty` 的属性和一个名为 `myMethod` 的方法。

**C++ (简化的概念示例):**

```c++
// 假设在某个地方定义了 MyObjectTemplate
v8::Local<v8::ObjectTemplate> MyObjectTemplate(v8::Isolate* isolate) {
  v8::Local<v8::ObjectTemplate> tpl = v8::ObjectTemplate::New(isolate);
  tpl->Set(v8::String::NewFromUtf8Literal(isolate, "myProperty"), v8::Number::New(isolate, 42));
  tpl->Set(v8::String::NewFromUtf8Literal(isolate, "myMethod"), v8::FunctionTemplate::New(isolate, MyNativeMethod));
  return tpl;
}

void MyNativeMethod(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // C++ 中 myMethod 的实现
  args.GetReturnValue().Set(v8::String::NewFromUtf8Literal(args.GetIsolate(), "Hello from C++!"));
}

// 在某个地方，你可能会使用这个模板来创建对象
v8::Local<v8::Function> constructor = ...; // 获取构造函数
v8::Local<v8::Object> myObjectInstance = constructor->NewInstance(context).ToLocalChecked();
```

当 V8 执行上面的 C++ 代码来创建 `myObjectInstance` 时，`api-natives.cc` 中的 `InstantiateObject` 函数（或与之相关的函数）会被调用。它会根据 `MyObjectTemplate` 中的定义，在 JavaScript 堆中分配内存，并设置 `myProperty` 的值为 42，并将 `myMethod` 关联到 C++ 的 `MyNativeMethod` 函数。

**JavaScript 中使用该对象：**

```javascript
let myObj = new MyObject(); // 假设 MyObject 可以在 JavaScript 中访问到
console.log(myObj.myProperty); // 输出: 42
console.log(myObj.myMethod());   // 输出: "Hello from C++!"
```

在这个 JavaScript 例子中，`myObj` 的结构和行为（拥有 `myProperty` 属性和 `myMethod` 方法）很大程度上是由 C++ 中 `MyObjectTemplate` 的定义以及 `api-natives.cc` 中实例化逻辑决定的。

**另一个 JavaScript 例子（关于函数模板）：**

**C++ (简化的概念示例):**

```c++
v8::Local<v8::FunctionTemplate> MyFunctionTemplate(v8::Isolate* isolate) {
  v8::Local<v8::FunctionTemplate> tpl = v8::FunctionTemplate::New(isolate, MyNativeFunction);
  return tpl;
}

void MyNativeFunction(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // C++ 中 MyNativeFunction 的实现
  int a = args[0]->Int32Value(args.GetIsolate()->GetCurrentContext()).FromJust();
  int b = args[1]->Int32Value(args.GetIsolate()->GetCurrentContext()).FromJust();
  args.GetReturnValue().Set(v8::Number::New(args.GetIsolate(), a + b));
}

// 在某个地方，你可能会使用这个模板来创建函数
v8::Local<v8::Function> myFunction = MyFunctionTemplate(isolate)->GetFunction(context).ToLocalChecked();
```

当 V8 执行上面的 C++ 代码来创建 `myFunction` 时，`api-natives.cc` 中的 `InstantiateFunction` 函数（或与之相关的函数）会被调用。它会根据 `MyFunctionTemplate` 的定义，创建一个 JavaScript 函数对象，并将该函数与 C++ 的 `MyNativeFunction` 关联起来。

**JavaScript 中使用该函数：**

```javascript
let result = myFunction(5, 3);
console.log(result); // 输出: 8
```

在这个 JavaScript 例子中，`myFunction` 的行为（接收两个参数并返回它们的和）是由 C++ 中 `MyNativeFunction` 的实现以及 `api-natives.cc` 中实例化逻辑决定的。

总而言之，`v8/src/api/api-natives.cc` 是 V8 引擎中一个至关重要的文件，它弥合了 C++ 和 JavaScript 之间的鸿沟，使得通过 C++ API 定义的 native 对象和函数能够在 JavaScript 环境中被创建和使用。

### 提示词
```
这是目录为v8/src/api/api-natives.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/api/api-natives.h"

#include "src/api/api-inl.h"
#include "src/common/globals.h"
#include "src/common/message-template.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/protectors-inl.h"
#include "src/heap/heap-inl.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/lookup.h"
#include "src/objects/templates.h"

namespace v8 {
namespace internal {

namespace {

class V8_NODISCARD InvokeScope {
 public:
  explicit InvokeScope(Isolate* isolate)
      : isolate_(isolate), save_context_(isolate) {}
  ~InvokeScope() {
    bool has_exception = isolate_->has_exception();
    if (has_exception) {
      isolate_->ReportPendingMessages();
    } else {
      isolate_->clear_pending_message();
    }
  }

 private:
  Isolate* isolate_;
  SaveContext save_context_;
};

MaybeHandle<JSObject> InstantiateObject(Isolate* isolate,
                                        Handle<ObjectTemplateInfo> data,
                                        Handle<JSReceiver> new_target,
                                        bool is_prototype);

MaybeHandle<JSFunction> InstantiateFunction(
    Isolate* isolate, Handle<NativeContext> native_context,
    Handle<FunctionTemplateInfo> data,
    MaybeHandle<Name> maybe_name = MaybeHandle<Name>());

MaybeHandle<JSFunction> InstantiateFunction(
    Isolate* isolate, Handle<FunctionTemplateInfo> data,
    MaybeHandle<Name> maybe_name = MaybeHandle<Name>()) {
  return InstantiateFunction(isolate, isolate->native_context(), data,
                             maybe_name);
}

MaybeHandle<Object> Instantiate(
    Isolate* isolate, Handle<Object> data,
    MaybeHandle<Name> maybe_name = MaybeHandle<Name>()) {
  if (IsFunctionTemplateInfo(*data)) {
    return InstantiateFunction(isolate, Cast<FunctionTemplateInfo>(data),
                               maybe_name);
  } else if (IsObjectTemplateInfo(*data)) {
    return InstantiateObject(isolate, Cast<ObjectTemplateInfo>(data),
                             Handle<JSReceiver>(), false);
  } else {
    return data;
  }
}

MaybeHandle<Object> DefineAccessorProperty(Isolate* isolate,
                                           Handle<JSObject> object,
                                           Handle<Name> name,
                                           Handle<Object> getter,
                                           Handle<Object> setter,
                                           PropertyAttributes attributes) {
  DCHECK(!IsFunctionTemplateInfo(*getter) ||
         Cast<FunctionTemplateInfo>(*getter)->should_cache());
  DCHECK(!IsFunctionTemplateInfo(*setter) ||
         Cast<FunctionTemplateInfo>(*setter)->should_cache());
  if (IsFunctionTemplateInfo(*getter) &&
      Cast<FunctionTemplateInfo>(*getter)->BreakAtEntry(isolate)) {
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, getter,
        InstantiateFunction(isolate, Cast<FunctionTemplateInfo>(getter)));
    DirectHandle<Code> trampoline = BUILTIN_CODE(isolate, DebugBreakTrampoline);
    Cast<JSFunction>(getter)->UpdateCode(*trampoline);
  }
  if (IsFunctionTemplateInfo(*setter) &&
      Cast<FunctionTemplateInfo>(*setter)->BreakAtEntry(isolate)) {
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, setter,
        InstantiateFunction(isolate, Cast<FunctionTemplateInfo>(setter)));
    DirectHandle<Code> trampoline = BUILTIN_CODE(isolate, DebugBreakTrampoline);
    Cast<JSFunction>(setter)->UpdateCode(*trampoline);
  }
  RETURN_ON_EXCEPTION(isolate, JSObject::DefineOwnAccessorIgnoreAttributes(
                                   object, name, getter, setter, attributes));
  return object;
}

MaybeHandle<Object> DefineDataProperty(Isolate* isolate,
                                       Handle<JSObject> object,
                                       Handle<Name> name,
                                       Handle<Object> prop_data,
                                       PropertyAttributes attributes) {
  Handle<Object> value;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, value,
                             Instantiate(isolate, prop_data, name));

  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, LookupIterator::OWN_SKIP_INTERCEPTOR);

#ifdef DEBUG
  Maybe<PropertyAttributes> maybe = JSReceiver::GetPropertyAttributes(&it);
  DCHECK(maybe.IsJust());
  if (it.IsFound()) {
    THROW_NEW_ERROR(
        isolate,
        NewTypeError(MessageTemplate::kDuplicateTemplateProperty, name));
  }
#endif

  MAYBE_RETURN_NULL(Object::AddDataProperty(&it, value, attributes,
                                            Just(ShouldThrow::kThrowOnError),
                                            StoreOrigin::kNamed));
  return value;
}

void DisableAccessChecks(Isolate* isolate, DirectHandle<JSObject> object) {
  Handle<Map> old_map(object->map(), isolate);
  // Copy map so it won't interfere constructor's initial map.
  DirectHandle<Map> new_map =
      Map::Copy(isolate, old_map, "DisableAccessChecks");
  new_map->set_is_access_check_needed(false);
  JSObject::MigrateToMap(isolate, object, new_map);
}

void EnableAccessChecks(Isolate* isolate, DirectHandle<JSObject> object) {
  Handle<Map> old_map(object->map(), isolate);
  // Copy map so it won't interfere constructor's initial map.
  DirectHandle<Map> new_map = Map::Copy(isolate, old_map, "EnableAccessChecks");
  new_map->set_is_access_check_needed(true);
  new_map->set_may_have_interesting_properties(true);
  JSObject::MigrateToMap(isolate, object, new_map);
}

class V8_NODISCARD AccessCheckDisableScope {
 public:
  AccessCheckDisableScope(Isolate* isolate, Handle<JSObject> obj)
      : isolate_(isolate),
        disabled_(obj->map()->is_access_check_needed()),
        obj_(obj) {
    if (disabled_) {
      DisableAccessChecks(isolate_, obj_);
    }
  }
  ~AccessCheckDisableScope() {
    if (disabled_) {
      EnableAccessChecks(isolate_, obj_);
    }
  }

 private:
  Isolate* isolate_;
  const bool disabled_;
  Handle<JSObject> obj_;
};

Tagged<Object> GetIntrinsic(Isolate* isolate, v8::Intrinsic intrinsic) {
  Handle<Context> native_context = isolate->native_context();
  DCHECK(!native_context.is_null());
  switch (intrinsic) {
#define GET_INTRINSIC_VALUE(name, iname) \
  case v8::k##name:                      \
    return native_context->iname();
    V8_INTRINSICS_LIST(GET_INTRINSIC_VALUE)
#undef GET_INTRINSIC_VALUE
  }
  return Tagged<Object>();
}

template <typename TemplateInfoT>
MaybeHandle<JSObject> ConfigureInstance(Isolate* isolate, Handle<JSObject> obj,
                                        Handle<TemplateInfoT> data) {
  RCS_SCOPE(isolate, RuntimeCallCounterId::kConfigureInstance);
  HandleScope scope(isolate);
  // Disable access checks while instantiating the object.
  AccessCheckDisableScope access_check_scope(isolate, obj);

  // Walk the inheritance chain and copy all accessors to current object.
  int max_number_of_properties = 0;
  Tagged<TemplateInfoT> info = *data;
  while (!info.is_null()) {
    Tagged<Object> props = info->property_accessors();
    if (!IsUndefined(props, isolate)) {
      max_number_of_properties += Cast<ArrayList>(props)->length();
    }
    info = info->GetParent(isolate);
  }

  if (max_number_of_properties > 0) {
    int valid_descriptors = 0;
    // Use a temporary FixedArray to accumulate unique accessors.
    Handle<FixedArray> array =
        isolate->factory()->NewFixedArray(max_number_of_properties);

    // TODO(leszeks): Avoid creating unnecessary handles for cases where we
    // don't need to append anything.
    for (Handle<TemplateInfoT> temp(*data, isolate); !(*temp).is_null();
         temp = handle(temp->GetParent(isolate), isolate)) {
      // Accumulate accessors.
      Tagged<Object> maybe_properties = temp->property_accessors();
      if (!IsUndefined(maybe_properties, isolate)) {
        valid_descriptors = AccessorInfo::AppendUnique(
            isolate, handle(maybe_properties, isolate), array,
            valid_descriptors);
      }
    }

    // Install accumulated accessors.
    for (int i = 0; i < valid_descriptors; i++) {
      Handle<AccessorInfo> accessor(Cast<AccessorInfo>(array->get(i)), isolate);
      Handle<Name> name(Cast<Name>(accessor->name()), isolate);
      JSObject::SetAccessor(obj, name, accessor,
                            accessor->initial_property_attributes())
          .Assert();
    }
  }

  Tagged<Object> maybe_property_list = data->property_list();
  if (IsUndefined(maybe_property_list, isolate)) return obj;
  DirectHandle<ArrayList> properties(Cast<ArrayList>(maybe_property_list),
                                     isolate);
  if (properties->length() == 0) return obj;

  int i = 0;
  for (int c = 0; c < data->number_of_properties(); c++) {
    auto name = handle(Cast<Name>(properties->get(i++)), isolate);
    Tagged<Object> bit = properties->get(i++);
    if (IsSmi(bit)) {
      PropertyDetails details(Cast<Smi>(bit));
      PropertyAttributes attributes = details.attributes();
      PropertyKind kind = details.kind();

      if (kind == PropertyKind::kData) {
        auto prop_data = handle(properties->get(i++), isolate);
        RETURN_ON_EXCEPTION(isolate, DefineDataProperty(isolate, obj, name,
                                                        prop_data, attributes));
      } else {
        auto getter = handle(properties->get(i++), isolate);
        auto setter = handle(properties->get(i++), isolate);
        RETURN_ON_EXCEPTION(
            isolate, DefineAccessorProperty(isolate, obj, name, getter, setter,
                                            attributes));
      }
    } else {
      // Intrinsic data property --- Get appropriate value from the current
      // context.
      PropertyDetails details(Cast<Smi>(properties->get(i++)));
      PropertyAttributes attributes = details.attributes();
      DCHECK_EQ(PropertyKind::kData, details.kind());

      v8::Intrinsic intrinsic =
          static_cast<v8::Intrinsic>(Smi::ToInt(properties->get(i++)));
      auto prop_data = handle(GetIntrinsic(isolate, intrinsic), isolate);

      RETURN_ON_EXCEPTION(isolate, DefineDataProperty(isolate, obj, name,
                                                      prop_data, attributes));
    }
  }
  return obj;
}

bool IsSimpleInstantiation(Isolate* isolate, Tagged<ObjectTemplateInfo> info,
                           Tagged<JSReceiver> new_target) {
  DisallowGarbageCollection no_gc;

  if (!IsJSFunction(new_target)) return false;
  Tagged<JSFunction> fun = Cast<JSFunction>(new_target);
  if (!fun->shared()->IsApiFunction()) return false;
  if (fun->shared()->api_func_data() != info->constructor()) return false;
  if (info->immutable_proto()) return false;
  return fun->native_context() == isolate->raw_native_context();
}

MaybeHandle<JSObject> InstantiateObject(Isolate* isolate,
                                        Handle<ObjectTemplateInfo> info,
                                        Handle<JSReceiver> new_target,
                                        bool is_prototype) {
  RCS_SCOPE(isolate, RuntimeCallCounterId::kInstantiateObject);
  Handle<JSFunction> constructor;
  bool should_cache = info->should_cache();
  if (!new_target.is_null()) {
    if (IsSimpleInstantiation(isolate, *info, *new_target)) {
      constructor = Cast<JSFunction>(new_target);
    } else {
      // Disable caching for subclass instantiation.
      should_cache = false;
    }
  }
  // Fast path.
  Handle<JSObject> result;
  if (should_cache && info->is_cached()) {
    if (TemplateInfo::ProbeInstantiationsCache<JSObject>(
            isolate, isolate->native_context(), info->serial_number(),
            TemplateInfo::CachingMode::kLimited)
            .ToHandle(&result)) {
      return isolate->factory()->CopyJSObject(result);
    }
  }

  if (constructor.is_null()) {
    Tagged<Object> maybe_constructor_info = info->constructor();
    if (IsUndefined(maybe_constructor_info, isolate)) {
      constructor = isolate->object_function();
    } else {
      // Enter a new scope.  Recursion could otherwise create a lot of handles.
      HandleScope scope(isolate);
      Handle<FunctionTemplateInfo> cons_templ(
          Cast<FunctionTemplateInfo>(maybe_constructor_info), isolate);
      Handle<JSFunction> tmp_constructor;
      ASSIGN_RETURN_ON_EXCEPTION(isolate, tmp_constructor,
                                 InstantiateFunction(isolate, cons_templ));
      constructor = scope.CloseAndEscape(tmp_constructor);
    }

    if (new_target.is_null()) new_target = constructor;
  }

  const auto new_js_object_type =
      constructor->has_initial_map() &&
              IsJSApiWrapperObject(constructor->initial_map())
          ? NewJSObjectType::kAPIWrapper
          : NewJSObjectType::kNoAPIWrapper;
  Handle<JSObject> object;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, object,
      JSObject::New(constructor, new_target, Handle<AllocationSite>::null(),
                    new_js_object_type));

  if (is_prototype) JSObject::OptimizeAsPrototype(object);

  ASSIGN_RETURN_ON_EXCEPTION(isolate, result,
                             ConfigureInstance(isolate, object, info));
  if (info->immutable_proto()) {
    JSObject::SetImmutableProto(isolate, object);
  }
  if (!is_prototype) {
    // Keep prototypes in slow-mode. Let them be lazily turned fast later on.
    // TODO(dcarney): is this necessary?
    JSObject::MigrateSlowToFast(result, 0, "ApiNatives::InstantiateObject");
    // Don't cache prototypes.
    if (should_cache) {
      TemplateInfo::CacheTemplateInstantiation<JSObject, ObjectTemplateInfo>(
          isolate, isolate->native_context(), info,
          TemplateInfo::CachingMode::kLimited, result);
      result = isolate->factory()->CopyJSObject(result);
    }
  }

  return result;
}

namespace {
MaybeHandle<Object> GetInstancePrototype(Isolate* isolate,
                                         Handle<Object> function_template) {
  // Enter a new scope.  Recursion could otherwise create a lot of handles.
  HandleScope scope(isolate);
  Handle<JSFunction> parent_instance;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, parent_instance,
      InstantiateFunction(isolate,
                          Cast<FunctionTemplateInfo>(function_template)));
  Handle<Object> instance_prototype;
  // TODO(cbruni): decide what to do here.
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instance_prototype,
      JSObject::GetProperty(isolate, parent_instance,
                            isolate->factory()->prototype_string()));
  return scope.CloseAndEscape(instance_prototype);
}
}  // namespace

MaybeHandle<JSFunction> InstantiateFunction(
    Isolate* isolate, Handle<NativeContext> native_context,
    Handle<FunctionTemplateInfo> data, MaybeHandle<Name> maybe_name) {
  RCS_SCOPE(isolate, RuntimeCallCounterId::kInstantiateFunction);
  bool should_cache = data->should_cache();
  if (should_cache && data->is_cached()) {
    Handle<JSObject> result;
    if (TemplateInfo::ProbeInstantiationsCache<JSObject>(
            isolate, native_context, data->serial_number(),
            TemplateInfo::CachingMode::kUnlimited)
            .ToHandle(&result)) {
      return Cast<JSFunction>(result);
    }
  }
  Handle<Object> prototype;
  if (!data->remove_prototype()) {
    Handle<Object> prototype_templ(data->GetPrototypeTemplate(), isolate);
    if (IsUndefined(*prototype_templ, isolate)) {
      Handle<Object> protoype_provider_templ(
          data->GetPrototypeProviderTemplate(), isolate);
      if (IsUndefined(*protoype_provider_templ, isolate)) {
        prototype = isolate->factory()->NewJSObject(
            handle(native_context->object_function(), isolate));
      } else {
        ASSIGN_RETURN_ON_EXCEPTION(
            isolate, prototype,
            GetInstancePrototype(isolate, protoype_provider_templ));
      }
    } else {
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, prototype,
          InstantiateObject(isolate, Cast<ObjectTemplateInfo>(prototype_templ),
                            Handle<JSReceiver>(), true));
    }
    Handle<Object> parent(data->GetParentTemplate(), isolate);
    if (!IsUndefined(*parent, isolate)) {
      Handle<Object> parent_prototype;
      ASSIGN_RETURN_ON_EXCEPTION(isolate, parent_prototype,
                                 GetInstancePrototype(isolate, parent));
      Handle<JSPrototype> checked_parent_prototype;
      CHECK(TryCast(parent_prototype, &checked_parent_prototype));
      JSObject::ForceSetPrototype(isolate, Cast<JSObject>(prototype),
                                  checked_parent_prototype);
    }
  }
  InstanceType function_type = JS_SPECIAL_API_OBJECT_TYPE;
  if (!data->needs_access_check() &&
      IsUndefined(data->GetNamedPropertyHandler(), isolate) &&
      IsUndefined(data->GetIndexedPropertyHandler(), isolate)) {
    function_type = v8_flags.experimental_embedder_instance_types
                        ? data->GetInstanceType()
                        : JS_API_OBJECT_TYPE;
    DCHECK(InstanceTypeChecker::IsJSApiObject(function_type));
  }

  Handle<JSFunction> function = ApiNatives::CreateApiFunction(
      isolate, native_context, data, prototype, function_type, maybe_name);
  if (should_cache) {
    // Cache the function.
    TemplateInfo::CacheTemplateInstantiation<JSObject, FunctionTemplateInfo>(
        isolate, native_context, data, TemplateInfo::CachingMode::kUnlimited,
        function);
  }
  MaybeHandle<JSObject> result = ConfigureInstance(isolate, function, data);
  if (result.is_null()) {
    // Uncache on error.
    TemplateInfo::UncacheTemplateInstantiation<FunctionTemplateInfo>(
        isolate, native_context, data, TemplateInfo::CachingMode::kUnlimited);
    return MaybeHandle<JSFunction>();
  }
  data->set_published(true);
  return function;
}

void AddPropertyToPropertyList(Isolate* isolate,
                               DirectHandle<TemplateInfo> templ, int length,
                               Handle<Object>* data) {
  Tagged<Object> maybe_list = templ->property_list();
  Handle<ArrayList> list;
  if (IsUndefined(maybe_list, isolate)) {
    list = ArrayList::New(isolate, length, AllocationType::kOld);
  } else {
    list = handle(Cast<ArrayList>(maybe_list), isolate);
  }
  templ->set_number_of_properties(templ->number_of_properties() + 1);
  for (int i = 0; i < length; i++) {
    DirectHandle<Object> value =
        data[i].is_null() ? Cast<Object>(isolate->factory()->undefined_value())
                          : data[i];
    list = ArrayList::Add(isolate, list, value);
  }
  templ->set_property_list(*list);
}

}  // namespace

// static
i::Handle<i::FunctionTemplateInfo>
ApiNatives::CreateAccessorFunctionTemplateInfo(
    i::Isolate* i_isolate, FunctionCallback callback, int length,
    SideEffectType side_effect_type) {
  // TODO(v8:5962): move FunctionTemplateNew() from api.cc here.
  auto isolate = reinterpret_cast<v8::Isolate*>(i_isolate);
  Local<FunctionTemplate> func_template = FunctionTemplate::New(
      isolate, callback, v8::Local<Value>{}, v8::Local<v8::Signature>{}, length,
      v8::ConstructorBehavior::kThrow, side_effect_type);
  return Utils::OpenHandle(*func_template);
}

MaybeHandle<JSFunction> ApiNatives::InstantiateFunction(
    Isolate* isolate, Handle<NativeContext> native_context,
    Handle<FunctionTemplateInfo> data, MaybeHandle<Name> maybe_name) {
  InvokeScope invoke_scope(isolate);
  return ::v8::internal::InstantiateFunction(isolate, native_context, data,
                                             maybe_name);
}

MaybeHandle<JSFunction> ApiNatives::InstantiateFunction(
    Isolate* isolate, Handle<FunctionTemplateInfo> data,
    MaybeHandle<Name> maybe_name) {
  InvokeScope invoke_scope(isolate);
  return ::v8::internal::InstantiateFunction(isolate, data, maybe_name);
}

MaybeHandle<JSObject> ApiNatives::InstantiateObject(
    Isolate* isolate, Handle<ObjectTemplateInfo> data,
    Handle<JSReceiver> new_target) {
  InvokeScope invoke_scope(isolate);
  return ::v8::internal::InstantiateObject(isolate, data, new_target, false);
}

MaybeHandle<JSObject> ApiNatives::InstantiateRemoteObject(
    DirectHandle<ObjectTemplateInfo> data) {
  Isolate* isolate = data->GetIsolate();
  InvokeScope invoke_scope(isolate);

  DirectHandle<FunctionTemplateInfo> constructor(
      Cast<FunctionTemplateInfo>(data->constructor()), isolate);
  DirectHandle<Map> object_map = isolate->factory()->NewContextlessMap(
      JS_SPECIAL_API_OBJECT_TYPE,
      JSSpecialObject::kHeaderSize +
          data->embedder_field_count() * kEmbedderDataSlotSize,
      TERMINAL_FAST_ELEMENTS_KIND);
  object_map->SetConstructor(*constructor);
  object_map->set_is_access_check_needed(true);
  object_map->set_may_have_interesting_properties(true);

  Handle<JSObject> object = isolate->factory()->NewJSObjectFromMap(
      object_map, AllocationType::kYoung, DirectHandle<AllocationSite>::null(),
      NewJSObjectType::kAPIWrapper);
  JSObject::ForceSetPrototype(isolate, object,
                              isolate->factory()->null_value());

  return object;
}

void ApiNatives::AddDataProperty(Isolate* isolate,
                                 DirectHandle<TemplateInfo> info,
                                 Handle<Name> name, Handle<Object> value,
                                 PropertyAttributes attributes) {
  PropertyDetails details(PropertyKind::kData, attributes,
                          PropertyConstness::kMutable);
  auto details_handle = handle(details.AsSmi(), isolate);
  Handle<Object> data[] = {name, details_handle, value};
  AddPropertyToPropertyList(isolate, info, arraysize(data), data);
}

void ApiNatives::AddDataProperty(Isolate* isolate,
                                 DirectHandle<TemplateInfo> info,
                                 Handle<Name> name, v8::Intrinsic intrinsic,
                                 PropertyAttributes attributes) {
  auto value = handle(Smi::FromInt(intrinsic), isolate);
  auto intrinsic_marker = isolate->factory()->true_value();
  PropertyDetails details(PropertyKind::kData, attributes,
                          PropertyConstness::kMutable);
  auto details_handle = handle(details.AsSmi(), isolate);
  Handle<Object> data[] = {name, intrinsic_marker, details_handle, value};
  AddPropertyToPropertyList(isolate, info, arraysize(data), data);
}

void ApiNatives::AddAccessorProperty(Isolate* isolate,
                                     DirectHandle<TemplateInfo> info,
                                     Handle<Name> name,
                                     Handle<FunctionTemplateInfo> getter,
                                     Handle<FunctionTemplateInfo> setter,
                                     PropertyAttributes attributes) {
  if (!getter.is_null()) getter->set_published(true);
  if (!setter.is_null()) setter->set_published(true);
  PropertyDetails details(PropertyKind::kAccessor, attributes,
                          PropertyConstness::kMutable);
  auto details_handle = handle(details.AsSmi(), isolate);
  Handle<Object> data[] = {name, details_handle, getter, setter};
  AddPropertyToPropertyList(isolate, info, arraysize(data), data);
}

void ApiNatives::AddNativeDataProperty(Isolate* isolate,
                                       DirectHandle<TemplateInfo> info,
                                       DirectHandle<AccessorInfo> property) {
  Tagged<Object> maybe_list = info->property_accessors();
  Handle<ArrayList> list;
  if (IsUndefined(maybe_list, isolate)) {
    list = ArrayList::New(isolate, 1, AllocationType::kOld);
  } else {
    list = handle(Cast<ArrayList>(maybe_list), isolate);
  }
  list = ArrayList::Add(isolate, list, property);
  info->set_property_accessors(*list);
}

Handle<JSFunction> ApiNatives::CreateApiFunction(
    Isolate* isolate, Handle<NativeContext> native_context,
    DirectHandle<FunctionTemplateInfo> obj, Handle<Object> prototype,
    InstanceType type, MaybeHandle<Name> maybe_name) {
  RCS_SCOPE(isolate, RuntimeCallCounterId::kCreateApiFunction);
  Handle<SharedFunctionInfo> shared =
      FunctionTemplateInfo::GetOrCreateSharedFunctionInfo(isolate, obj,
                                                          maybe_name);
  // To simplify things, API functions always have shared name.
  DCHECK(shared->HasSharedName());

  Handle<JSFunction> result =
      Factory::JSFunctionBuilder{isolate, shared, native_context}.Build();

  if (obj->remove_prototype()) {
    DCHECK(prototype.is_null());
    DCHECK(result->shared()->IsApiFunction());
    DCHECK(!IsConstructor(*result));
    DCHECK(!result->has_prototype_slot());
    return result;
  }

  // Down from here is only valid for API functions that can be used as a
  // constructor (don't set the "remove prototype" flag).
  DCHECK(result->has_prototype_slot());

  if (obj->read_only_prototype()) {
    result->set_map(isolate,
                    *isolate->sloppy_function_with_readonly_prototype_map());
  }

  if (IsTheHole(*prototype, isolate)) {
    prototype = isolate->factory()->NewFunctionPrototype(result);
  } else if (IsUndefined(obj->GetPrototypeProviderTemplate(), isolate)) {
    JSObject::AddProperty(isolate, Cast<JSObject>(prototype),
                          isolate->factory()->constructor_string(), result,
                          DONT_ENUM);
  }

  int embedder_field_count = 0;
  bool immutable_proto = false;
  if (!IsUndefined(obj->GetInstanceTemplate(), isolate)) {
    DirectHandle<ObjectTemplateInfo> GetInstanceTemplate(
        Cast<ObjectTemplateInfo>(obj->GetInstanceTemplate()), isolate);
    embedder_field_count = GetInstanceTemplate->embedder_field_count();
    immutable_proto = GetInstanceTemplate->immutable_proto();
  }

  // JSFunction requires information about the prototype slot.
  DCHECK(!InstanceTypeChecker::IsJSFunction(type));
  int instance_size = JSObject::GetHeaderSize(type) +
                      kEmbedderDataSlotSize * embedder_field_count;

  Handle<Map> map = isolate->factory()->NewContextfulMap(
      native_context, type, instance_size, TERMINAL_FAST_ELEMENTS_KIND);

  // Mark as undetectable if needed.
  if (obj->undetectable()) {
    // We only allow callable undetectable receivers here, since this whole
    // undetectable business is only to support document.all, which is both
    // undetectable and callable. If we ever see the need to have an object
    // that is undetectable but not callable, we need to update the types.h
    // to allow encoding this.
    CHECK(!IsUndefined(obj->GetInstanceCallHandler(), isolate));

    if (Protectors::IsNoUndetectableObjectsIntact(isolate)) {
      Protectors::InvalidateNoUndetectableObjects(isolate);
    }
    map->set_is_undetectable(true);
  }

  // Mark as needs_access_check if needed.
  if (obj->needs_access_check()) {
    map->set_is_access_check_needed(true);
    map->set_may_have_interesting_properties(true);
  }

  // Set interceptor information in the map.
  if (!IsUndefined(obj->GetNamedPropertyHandler(), isolate)) {
    map->set_has_named_interceptor(true);
    map->set_may_have_interesting_properties(true);
  }
  if (!IsUndefined(obj->GetIndexedPropertyHandler(), isolate)) {
    map->set_has_indexed_interceptor(true);
  }

  // Mark instance as callable in the map.
  if (!IsUndefined(obj->GetInstanceCallHandler(), isolate)) {
    map->set_is_callable(true);
    map->set_is_constructor(!obj->undetectable());
  }

  if (immutable_proto) map->set_is_immutable_proto(true);

  JSFunction::SetInitialMap(isolate, result, map, Cast<JSObject>(prototype));
  return result;
}

}  // namespace internal
}  // namespace v8
```