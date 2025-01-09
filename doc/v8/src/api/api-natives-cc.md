Response:
Let's break down the thought process for analyzing this C++ code.

1. **Initial Scan and Keywords:**  The first step is a quick scan looking for recognizable keywords and structures. Things that jump out are: `#include`, `namespace v8::internal`, class definitions (`InvokeScope`, `AccessCheckDisableScope`), function definitions (`InstantiateObject`, `InstantiateFunction`, `DefineAccessorProperty`, `DefineDataProperty`, `AddDataProperty`, `AddAccessorProperty`, etc.), and comments. The copyright notice also confirms it's V8 code.

2. **Identify Core Functionality:**  Based on the function names, a central theme emerges: object and function instantiation. Keywords like "TemplateInfo", "ObjectTemplateInfo", and "FunctionTemplateInfo" suggest this code deals with the API used to create JavaScript objects and functions from C++. The presence of "AccessorProperty" and "DataProperty" reinforces this idea.

3. **Namespace Context:**  The `namespace v8::internal` is crucial. It tells us this code is part of V8's *internal* implementation, not the public API directly exposed to embedders. This implies a lower-level role in the instantiation process.

4. **Class Analysis (Helper Classes):**
   * **`InvokeScope`:** The constructor saves the current context, and the destructor checks for and reports/clears pending exceptions. This hints at managing the execution environment and error handling within the instantiation process.
   * **`AccessCheckDisableScope`:**  This clearly manipulates the `is_access_check_needed` flag on a `JSObject`'s map. This points to controlling security checks related to accessing object properties. The scope suggests it's a temporary disabling/enabling mechanism.

5. **Function Analysis (Key Instantiation Functions):**
   * **`InstantiateObject`:**  This function takes `ObjectTemplateInfo` and creates `JSObject` instances. The logic handles caching, constructor invocation, prototype setup, and potentially disabling access checks. The `is_prototype` parameter suggests it's also used for creating prototype objects.
   * **`InstantiateFunction`:** Similar to `InstantiateObject`, but for creating `JSFunction` instances from `FunctionTemplateInfo`. It manages prototypes, caching, and sets up the function's internal structure. The multiple overloads (one with `NativeContext`) are important to notice.
   * **`DefineAccessorProperty` and `DefineDataProperty`:** These clearly handle adding properties to JavaScript objects, differentiating between accessor (getter/setter) and data properties. The instantiation of getter/setter functions within these functions is noteworthy.

6. **Connecting to JavaScript Concepts:** The names of the C++ functions strongly correlate with JavaScript concepts:
   * "ObjectTemplate" and "FunctionTemplate" are used in the V8 C++ API to define the structure and behavior of JavaScript objects and functions.
   * "Accessor" and "Data Property" are fundamental property types in JavaScript.
   * "Prototype" is a core concept in JavaScript's inheritance model.
   * "Constructor" is used to create new instances of objects.

7. **Code Logic Inference:**
   * **Caching:** The code explicitly checks for and utilizes caches for both object and function instantiations. This is an optimization to speed up repeated instantiations.
   * **Access Checks:**  The `AccessCheckDisableScope` clearly shows the temporary disabling of access checks during object configuration. This is likely to avoid triggering access checks on partially initialized objects.
   * **Prototype Chain:** The code iterates through the inheritance chain of templates to collect accessors and set up the prototype chain of the instantiated objects/functions.
   * **Property Definition:**  The `DefineDataProperty` and `DefineAccessorProperty` functions handle different property types and attributes.

8. **Hypothetical Input/Output:** To illustrate the logic, consider a simplified example:
   * **Input:** An `ObjectTemplateInfo` describing an object with a property named "x".
   * **Output:** A `JSObject` instance with a property "x".

9. **Common Programming Errors:** Thinking about how developers interact with the V8 API helps identify potential errors:
   * **Incorrectly defining templates:** Forgetting to set the prototype, or defining conflicting properties.
   * **Misunderstanding caching:**  Assuming changes to a template will automatically update already instantiated objects.
   * **Access check issues:**  Encountering access check failures if not properly managed.

10. **Torque Check:** The filename extension `.cc` immediately indicates this is *not* a Torque file. Torque files use the `.tq` extension.

11. **JavaScript Examples:**  Based on the C++ functionality, construct corresponding JavaScript examples that demonstrate the concepts being implemented internally. This solidifies the understanding of the C++ code's purpose.

12. **Refinement and Organization:**  Finally, organize the findings logically, starting with the basic function, then diving into details, providing examples, and addressing potential errors. Use clear headings and bullet points for readability.

**(Self-Correction during the process):** Initially, I might focus too much on the low-level details of memory management. However, realizing the context is *API* related shifts the focus to the interaction between C++ and JavaScript object creation. Also, I might initially overlook the significance of the caching mechanisms, but noticing the repeated checks for cached instances highlights its importance as an optimization. Recognizing the `namespace v8::internal` early on is crucial to understanding the scope and purpose of this code.
好的，让我们来分析一下 `v8/src/api/api-natives.cc` 这个 V8 源代码文件的功能。

**主要功能概览:**

`v8/src/api/api-natives.cc` 文件是 V8 JavaScript 引擎中负责 **实现 C++ 和 JavaScript 之间桥梁的关键部分，特别是关于原生对象和函数的创建和管理**。  它定义了一些帮助函数，用于将 C++ 中定义的数据结构（例如 `ObjectTemplateInfo` 和 `FunctionTemplateInfo`）实例化为可以在 JavaScript 中使用的对象和函数。

**具体功能点:**

1. **对象实例化 (`InstantiateObject`)**:
   - 该函数负责根据 `ObjectTemplateInfo` 创建新的 JavaScript 对象。
   - `ObjectTemplateInfo` 包含了创建对象所需的元数据，例如属性、方法、内部字段等。
   - 它处理原型链的设置，以及是否需要进行访问检查。
   - 它还支持缓存机制，如果启用了缓存，它可以重用之前创建的对象实例。
   - **JavaScript 关联:**  这与使用 `new` 关键字和自定义构造函数创建对象密切相关。例如，如果你在 C++ 中定义了一个模板，然后在 JavaScript 中使用 `new` 来创建该类型的对象，`InstantiateObject` 就会被调用。

   ```javascript
   // 假设 C++ 中定义了一个名为 MyObject 的模板
   const obj = new MyObject();
   ```

2. **函数实例化 (`InstantiateFunction`)**:
   - 该函数负责根据 `FunctionTemplateInfo` 创建新的 JavaScript 函数。
   - `FunctionTemplateInfo` 包含了函数的回调函数（C++ 实现）、参数信息、原型等。
   - 它也处理原型链的设置和缓存。
   - **JavaScript 关联:**  这与在 C++ 中定义原生函数，然后在 JavaScript 中调用这些函数相关。

   ```javascript
   // 假设 C++ 中定义了一个名为 nativeFunction 的原生函数
   nativeFunction();
   ```

3. **属性定义 (`DefineDataProperty`, `DefineAccessorProperty`)**:
   - 这些函数用于在 JavaScript 对象上定义属性。
   - `DefineDataProperty` 用于定义普通的数据属性。
   - `DefineAccessorProperty` 用于定义带有 getter 和 setter 的访问器属性。
   - 它们都涉及到属性的特性（例如，是否可枚举、可配置、可写）。
   - **JavaScript 关联:**  这对应于在 JavaScript 中使用点号或方括号来定义或修改对象的属性。

   ```javascript
   const obj = {};
   obj.name = "example"; // 对应 DefineDataProperty
   Object.defineProperty(obj, 'age', {
       get() { return this._age; }, // 对应 DefineAccessorProperty (getter)
       set(value) { this._age = value; } // 对应 DefineAccessorProperty (setter)
   });
   ```

4. **访问检查控制 (`DisableAccessChecks`, `EnableAccessChecks`, `AccessCheckDisableScope`)**:
   - 这些机制用于临时禁用或启用对 JavaScript 对象的访问检查。
   - 访问检查是一种安全机制，用于控制对特定对象或属性的访问权限。
   - 在某些需要高性能或在对象构造过程中，可能需要临时禁用访问检查。
   - **JavaScript 关联:**  这通常在涉及到原生对象的操作时在底层发生，开发者一般不会直接控制。但在涉及到 Proxy 对象或有安全限制的对象时，访问检查会起作用。

5. **原生属性处理 (`AddDataProperty`, `AddAccessorProperty`, `AddNativeDataProperty`)**:
   - 这些函数用于向 `TemplateInfo` 对象添加属性信息，以便在实例化对象时使用。
   - 它们是在 C++ 中预先定义对象或函数的结构。
   - **JavaScript 关联:**  这些操作在 C++ 代码中定义了 JavaScript 对象的“蓝图”，最终影响 JavaScript 中对象的结构和行为。

6. **内置属性获取 (`GetIntrinsic`)**:
   - 此函数用于获取 V8 引擎的内置对象或函数，例如 `Object.prototype` 等。
   - **JavaScript 关联:**  这使得 C++ 代码能够访问和操作 JavaScript 的核心对象。

7. **配置实例 (`ConfigureInstance`)**:
   - 此函数在对象实例化后执行，用于配置对象的属性，包括从模板继承的属性和访问器。

8. **创建 API 函数 (`CreateApiFunction`)**:
   - 此函数创建用于连接 C++ 函数到 JavaScript 的 `JSFunction` 对象。
   - 它处理共享函数信息、原型设置、以及与 API 相关的特殊属性。

**关于 `.tq` 扩展名:**

你提到如果 `v8/src/api/api-natives.cc` 以 `.tq` 结尾，那它将是一个 V8 Torque 源代码文件。 **你的理解是正确的。** Torque 是 V8 用来编写高性能、类型安全的内部函数的领域特定语言。  `api-natives.cc` 本身是 C++ 文件，但它可能调用或涉及到由 Torque 编写的代码。

**代码逻辑推理示例:**

**假设输入:**

-  C++ 代码中有一个 `ObjectTemplateInfo` 实例 `myTemplate`，它定义了一个名为 `value` 的数据属性，初始值为 10。
-  JavaScript 代码执行 `const obj = new MyObjectCreatedFromTemplate();`

**输出:**

-  `InstantiateObject` 函数会被调用。
-  新创建的 JavaScript 对象 `obj` 将会有一个名为 `value` 的属性，其值为 10。

**用户常见的编程错误示例 (与 V8 API 使用相关，而不是直接操作 `api-natives.cc`):**

1. **忘记设置原型:** 在创建函数模板或对象模板时，如果忘记正确设置原型，可能导致 JavaScript 中创建的对象无法继承预期的属性和方法。

   ```c++
   // 错误示例：没有设置原型模板
   v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate, MyFunction);
   // ... 创建对象，但可能缺少预期的原型链
   ```

2. **在不适当的时候修改模板:**  一旦模板被用于创建对象，修改模板的某些属性可能不会影响已经创建的对象。开发者可能错误地认为修改模板会动态更新所有实例。

3. **混淆局部和全局模板:**  如果模板创建在错误的上下文中，可能会导致在 JavaScript 中无法访问或行为异常。

4. **不正确地处理访问检查:**  如果开发者在 C++ 中自定义了访问控制逻辑，但没有正确地与 V8 的访问检查机制集成，可能会导致意外的访问错误或安全漏洞。

**总结:**

`v8/src/api/api-natives.cc` 是 V8 引擎中至关重要的一个文件，它实现了 C++ 代码创建和操作 JavaScript 对象和函数的核心逻辑。它连接了 V8 的 C++ 内部和 JavaScript 外部，使得开发者可以使用 C++ 扩展 V8 的功能。  虽然开发者通常不会直接修改这个文件，但理解其功能有助于更好地理解 V8 的内部工作原理以及如何使用 V8 的 C++ API。

Prompt: 
```
这是目录为v8/src/api/api-natives.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api-natives.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
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

"""

```