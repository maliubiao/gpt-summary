Response: Let's break down the thought process for analyzing this C++ code and generating the summary.

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and its relation to JavaScript, with JavaScript examples.

2. **Initial Scan and Keywords:** Quickly scan the file for recognizable C++ keywords and V8-specific terms. Keywords like `#include`, `namespace v8::internal`, `class Accessors`, `static`, and function definitions stand out. V8-specific terms like `Isolate`, `Handle`, `AccessorInfo`, `JSObject`, `JSArray`, `String`, `Name`, and callbacks like `AccessorNameGetterCallback` are crucial. The presence of "Getter" and "Setter" in function names is also a strong indicator of accessor-related functionality.

3. **Identify the Core Purpose:** The class name `Accessors` strongly suggests that this file is about defining and managing property accessors in the V8 engine. The presence of `MakeAccessor` confirms this. The file seems to be involved in bridging the gap between C++ implementation details and how JavaScript accesses properties.

4. **Analyze `MakeAccessor`:** This function is clearly a factory for creating `AccessorInfo` objects. It takes a name (property name), a getter callback, and an optional setter callback. This is the foundation for defining how specific properties are accessed and modified.

5. **Look for Specific Accessors:**  The file contains numerous functions named `*Getter` and `*Setter`, like `ArrayLengthGetter`, `ArrayLengthSetter`, `StringLengthGetter`, `FunctionPrototypeGetter`, etc. These strongly suggest the file defines accessors for built-in JavaScript properties. List them out mentally or physically.

6. **Infer Functionality from Accessors:** By examining the names of the getter and setter functions, we can infer the functionality they provide:
    * `ArrayLengthGetter`/`Setter`:  Handles accessing and setting the `length` property of JavaScript arrays.
    * `StringLengthGetter`: Handles accessing the `length` property of JavaScript strings.
    * `FunctionPrototypeGetter`/`Setter`:  Handles accessing and setting the `prototype` property of JavaScript functions.
    * `FunctionNameGetter`: Handles accessing the `name` property of JavaScript functions.
    * `FunctionArgumentsGetter`:  Handles accessing the `arguments` object inside functions.
    * `FunctionCallerGetter`: Handles accessing the deprecated `caller` property of functions.
    * `BoundFunctionLengthGetter`/`NameGetter`: Handles accessing `length` and `name` of bound functions.
    * `WrappedFunctionLengthGetter`/`NameGetter`: Handles accessing `length` and `name` of wrapped functions.
    * `ModuleNamespaceEntryGetter`/`Setter`: Handles accessing properties of module namespace objects.
    * `ErrorStackGetter`/`Setter`: Handles accessing and setting the `stack` property of error objects.
    * `ArgumentsIteratorGetter`: Handles getting the iterator for arguments objects.

7. **Connect to JavaScript:** Now, link the identified C++ functionality to corresponding JavaScript concepts. For each accessor, think about how that property is used and behaves in JavaScript.

8. **Generate JavaScript Examples:** For each key accessor, create a concise JavaScript example demonstrating its usage. Focus on showing how the getter retrieves the value and how the setter (if present) modifies it. Use simple and illustrative examples.

9. **Address the `ReconfigureToDataProperty` Function:** Notice the `ReconfigureToDataProperty` function and how it's used as a default setter in some `MakeAccessor` calls. Explain its role in converting an accessor property into a regular data property.

10. **Consider Edge Cases and Less Obvious Parts:**  Note the handling of `arguments`, `caller` (and its deprecation/security concerns), bound functions, wrapped functions, and module namespaces. These are more advanced JavaScript features that this file touches upon.

11. **Structure the Summary:** Organize the findings logically:
    * Start with a high-level overview of the file's purpose.
    * Detail the core mechanism (`MakeAccessor`).
    * List and explain the specific accessors and their JavaScript counterparts, providing examples.
    * Mention other important functions like `ReconfigureToDataProperty`.
    * Conclude with a summary of the file's overall role.

12. **Refine and Edit:** Review the generated summary for clarity, accuracy, and completeness. Ensure the language is precise and easy to understand. Double-check the JavaScript examples for correctness. For instance, initially, I might forget to mention that `caller` is deprecated and has security implications, but reviewing the code would remind me of those details. Similarly, I might initially just say "handles array length" but refining it to "handles accessing and setting the `length` property of JavaScript arrays" is more precise.

By following these steps, we can systematically analyze the C++ code and create a comprehensive and informative summary that addresses the prompt's requirements. The key is to connect the low-level C++ implementation details to the high-level JavaScript concepts they enable.
这个C++源代码文件 `accessors.cc` 的功能是 **定义和实现了 V8 JavaScript 引擎中内置对象的属性访问器 (accessors)**。

更具体地说，它做了以下几件事：

1. **提供创建访问器的工具:**  `Accessors::MakeAccessor` 函数是一个工厂方法，用于创建 `AccessorInfo` 对象。`AccessorInfo` 存储了属性的名称以及用于获取 (getter) 和设置 (setter) 属性值的 C++ 函数指针。

2. **实现内置属性的 getter 和 setter:** 文件中定义了大量静态函数，如 `ArrayLengthGetter`、`ArrayLengthSetter`、`StringLengthGetter`、`FunctionPrototypeGetter`、`FunctionPrototypeSetter` 等。这些函数是特定内置属性的实际访问器实现。当 JavaScript 代码尝试访问或修改这些属性时，V8 引擎会调用这些 C++ 函数。

3. **处理特定的内置属性:** 这些访问器涵盖了 JavaScript 中许多重要的内置属性，例如：
    * **`Array.prototype.length`**: 用于获取和设置数组的长度。
    * **`String.prototype.length`**: 用于获取字符串的长度。
    * **`Function.prototype`**: 用于获取和设置函数的原型对象。
    * **`Function.prototype.name`**: 用于获取函数的名称。
    * **`Function.prototype.arguments`**: 用于获取函数调用时的参数对象（已废弃，但在某些上下文中仍然存在）。
    * **`Function.prototype.caller`**: 用于获取调用当前函数的函数（已废弃，存在安全风险）。
    * **`Module Namespace` 的条目**:  用于访问 ES 模块导出的内容。
    * **`Bound Function` 的 `length` 和 `name`**: 用于获取绑定函数的长度和名称。
    * **`Error.prototype.stack`**: 用于获取和设置错误对象的堆栈信息。
    * **`Symbol.iterator` (用于 `arguments` 对象)**:  用于获取 `arguments` 对象的迭代器。

4. **提供将访问器重新配置为数据属性的功能:** `Accessors::ReconfigureToDataProperty` 函数允许将一个定义为访问器的属性动态地更改为一个普通的数据属性。

**与 JavaScript 的关系以及 JavaScript 示例:**

`accessors.cc` 文件直接影响着 JavaScript 中对内置对象属性的访问和修改行为。当你在 JavaScript 中操作这些内置属性时，V8 引擎内部很可能会调用这里定义的 C++ 函数。

以下是一些 JavaScript 示例，说明了 `accessors.cc` 中定义的访问器是如何在幕后工作的：

**1. `Array.prototype.length`:**

```javascript
const arr = [1, 2, 3];
console.log(arr.length); // JavaScript 调用 ArrayLengthGetter (C++)

arr.length = 5; // JavaScript 调用 ArrayLengthSetter (C++)
console.log(arr); // 输出: [ 1, 2, 3, <2 empty items> ]
```

**解释:** 当 JavaScript 代码访问 `arr.length` 时，V8 引擎会调用 `ArrayLengthGetter` 函数，该函数会从 `JSArray` 对象中读取长度信息并返回。当 `arr.length = 5` 被执行时，V8 会调用 `ArrayLengthSetter` 函数，该函数会更新 `JSArray` 对象的长度，并可能进行内存重新分配。

**2. `String.prototype.length`:**

```javascript
const str = "hello";
console.log(str.length); // JavaScript 调用 StringLengthGetter (C++)
```

**解释:** 访问字符串的 `length` 属性会触发 `StringLengthGetter` 函数，该函数会读取 `String` 对象的长度并返回。

**3. `Function.prototype`:**

```javascript
function myFunction() {}
console.log(myFunction.prototype); // JavaScript 调用 FunctionPrototypeGetter (C++)

myFunction.prototype = { customProperty: 'value' }; // JavaScript 调用 FunctionPrototypeSetter (C++)
console.log(myFunction.prototype.customProperty); // 输出: value
```

**解释:**  获取 `myFunction.prototype` 会调用 `FunctionPrototypeGetter`，该函数会返回函数的原型对象。设置 `myFunction.prototype` 会调用 `FunctionPrototypeSetter`，该函数会更新函数的原型对象。

**4. `Function.prototype.name`:**

```javascript
function myFunction() {}
console.log(myFunction.name); // JavaScript 调用 FunctionNameGetter (C++)
```

**解释:** 访问函数的 `name` 属性会调用 `FunctionNameGetter`，该函数会返回函数的名称字符串。

**5. `Error.prototype.stack`:**

```javascript
try {
  throw new Error("Something went wrong");
} catch (e) {
  console.log(e.stack); // JavaScript 调用 ErrorStackGetter (C++)
}

const err = new Error("Test");
err.stack = "Custom stack trace"; // JavaScript 调用 ErrorStackSetter (C++)
console.log(err.stack); // 输出: Custom stack trace
```

**解释:** 获取错误对象的 `stack` 属性会调用 `ErrorStackGetter`，该函数会生成并返回堆栈跟踪信息。设置 `stack` 属性会调用 `ErrorStackSetter`，允许修改错误对象的堆栈信息。

**总结:**

`v8/src/builtins/accessors.cc` 是 V8 引擎的关键组成部分，它将 C++ 代码连接到 JavaScript 的内置对象属性访问。它定义了当 JavaScript 代码尝试读取或写入这些属性时实际执行的底层操作，是理解 JavaScript 引擎内部工作原理的重要一环。

### 提示词
```
这是目录为v8/src/builtins/accessors.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/accessors.h"

#include "src/api/api-inl.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/execution.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/messages.h"
#include "src/heap/factory.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/contexts.h"
#include "src/objects/field-index-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-shared-array-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/property-details.h"
#include "src/objects/prototype.h"

namespace v8 {
namespace internal {

Handle<AccessorInfo> Accessors::MakeAccessor(
    Isolate* isolate, Handle<Name> name, AccessorNameGetterCallback getter,
    AccessorNameBooleanSetterCallback setter) {
  Factory* factory = isolate->factory();
  name = factory->InternalizeName(name);
  Handle<AccessorInfo> info = factory->NewAccessorInfo();
  {
    DisallowGarbageCollection no_gc;
    Tagged<AccessorInfo> raw = *info;
    raw->set_is_sloppy(false);
    raw->set_replace_on_access(false);
    raw->set_getter_side_effect_type(SideEffectType::kHasSideEffect);
    raw->set_setter_side_effect_type(SideEffectType::kHasSideEffect);
    raw->set_name(*name);
    raw->set_getter(isolate, reinterpret_cast<Address>(getter));
    if (setter == nullptr) setter = &ReconfigureToDataProperty;
    raw->set_setter(isolate, reinterpret_cast<Address>(setter));
  }
  return info;
}

static V8_INLINE bool CheckForName(Isolate* isolate, Handle<Name> name,
                                   Handle<String> property_name, int offset,
                                   FieldIndex::Encoding encoding,
                                   FieldIndex* index) {
  if (Name::Equals(isolate, name, property_name)) {
    *index = FieldIndex::ForInObjectOffset(offset, encoding);
    return true;
  }
  return false;
}

// Returns true for properties that are accessors to object fields.
// If true, *object_offset contains offset of object field.
bool Accessors::IsJSObjectFieldAccessor(Isolate* isolate, DirectHandle<Map> map,
                                        Handle<Name> name, FieldIndex* index) {
  if (map->is_dictionary_map()) {
    // There are not descriptors in a dictionary mode map.
    return false;
  }

  switch (map->instance_type()) {
    case JS_ARRAY_TYPE:
      return CheckForName(isolate, name, isolate->factory()->length_string(),
                          JSArray::kLengthOffset, FieldIndex::kTagged, index);
    default:
      if (map->instance_type() < FIRST_NONSTRING_TYPE) {
        return CheckForName(isolate, name, isolate->factory()->length_string(),
                            offsetof(String, length_), FieldIndex::kWord32,
                            index);
      }

      return false;
  }
}

V8_WARN_UNUSED_RESULT MaybeHandle<Object>
Accessors::ReplaceAccessorWithDataProperty(Isolate* isolate,
                                           Handle<JSAny> receiver,
                                           Handle<JSObject> holder,
                                           Handle<Name> name,
                                           Handle<Object> value) {
  LookupIterator it(isolate, receiver, PropertyKey(isolate, name), holder,
                    LookupIterator::OWN_SKIP_INTERCEPTOR);
  // Skip any access checks we might hit. This accessor should never hit in a
  // situation where the caller does not have access.
  while (it.state() == LookupIterator::ACCESS_CHECK) {
    CHECK(it.HasAccess());
    it.Next();
  }
  DCHECK(holder.is_identical_to(it.GetHolder<JSObject>()));
  CHECK_EQ(LookupIterator::ACCESSOR, it.state());
  it.ReconfigureDataProperty(value, it.property_attributes());
  return value;
}

// Allow usages of v8::PropertyCallbackInfo<T>::Holder() for now.
// TODO(https://crbug.com/333672197): remove.
START_ALLOW_USE_DEPRECATED()

//
// Accessors::ReconfigureToDataProperty
//
void Accessors::ReconfigureToDataProperty(
    v8::Local<v8::Name> key, v8::Local<v8::Value> val,
    const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  RCS_SCOPE(isolate, RuntimeCallCounterId::kReconfigureToDataProperty);
  HandleScope scope(isolate);
  Handle<JSReceiver> receiver = Utils::OpenHandle(*info.This());
  Handle<JSObject> holder = Cast<JSObject>(Utils::OpenHandle(*info.Holder()));
  Handle<Name> name = Utils::OpenHandle(*key);
  Handle<Object> value = Utils::OpenHandle(*val);
  MaybeHandle<Object> result = Accessors::ReplaceAccessorWithDataProperty(
      isolate, receiver, holder, name, value);
  if (!result.is_null()) {
    info.GetReturnValue().Set(true);
  }
}

//
// Accessors::ArgumentsIterator
//

void Accessors::ArgumentsIteratorGetter(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  DisallowGarbageCollection no_gc;
  HandleScope scope(isolate);
  Tagged<Object> result = isolate->native_context()->array_values_iterator();
  info.GetReturnValue().Set(Utils::ToLocal(Handle<Object>(result, isolate)));
}

Handle<AccessorInfo> Accessors::MakeArgumentsIteratorInfo(Isolate* isolate) {
  Handle<Name> name = isolate->factory()->iterator_symbol();
  return MakeAccessor(isolate, name, &ArgumentsIteratorGetter, nullptr);
}

//
// Accessors::ArrayLength
//

void Accessors::ArrayLengthGetter(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  RCS_SCOPE(isolate, RuntimeCallCounterId::kArrayLengthGetter);
  DisallowGarbageCollection no_gc;
  HandleScope scope(isolate);
  Tagged<JSArray> holder =
      Cast<JSArray>(*Utils::OpenDirectHandle(*info.Holder()));
  Tagged<Object> result = holder->length();
  info.GetReturnValue().Set(Utils::ToLocal(Handle<Object>(result, isolate)));
}

void Accessors::ArrayLengthSetter(
    v8::Local<v8::Name> name, v8::Local<v8::Value> val,
    const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  RCS_SCOPE(isolate, RuntimeCallCounterId::kArrayLengthSetter);
  HandleScope scope(isolate);

  DCHECK(Object::SameValue(*Utils::OpenDirectHandle(*name),
                           ReadOnlyRoots(isolate).length_string()));

  Handle<JSReceiver> object = Utils::OpenHandle(*info.Holder());
  Handle<JSArray> array = Cast<JSArray>(object);
  Handle<Object> length_obj = Utils::OpenHandle(*val);

  bool was_readonly = JSArray::HasReadOnlyLength(array);

  uint32_t length = 0;
  if (!JSArray::AnythingToArrayLength(isolate, length_obj, &length)) {
    return;
  }

  if (!was_readonly && V8_UNLIKELY(JSArray::HasReadOnlyLength(array))) {
    // AnythingToArrayLength() may have called setter re-entrantly and modified
    // its property descriptor. Don't perform this check if "length" was
    // previously readonly, as this may have been called during
    // DefineOwnPropertyIgnoreAttributes().
    if (length == Object::NumberValue(array->length())) {
      info.GetReturnValue().Set(true);
    } else if (info.ShouldThrowOnError()) {
      Factory* factory = isolate->factory();
      isolate->Throw(*factory->NewTypeError(
          MessageTemplate::kStrictReadOnlyProperty, Utils::OpenHandle(*name),
          i::Object::TypeOf(isolate, object), object));
    } else {
      info.GetReturnValue().Set(false);
    }
    return;
  }

  if (JSArray::SetLength(array, length).IsNothing()) {
    // TODO(victorgomes): AccessorNameBooleanSetterCallback does not handle
    // exceptions.
    FATAL("Fatal JavaScript invalid array length %u", length);
    UNREACHABLE();
  }

  uint32_t actual_new_len = 0;
  CHECK(Object::ToArrayLength(array->length(), &actual_new_len));
  // Fail if there were non-deletable elements.
  if (actual_new_len != length) {
    if (info.ShouldThrowOnError()) {
      Factory* factory = isolate->factory();
      isolate->Throw(*factory->NewTypeError(
          MessageTemplate::kStrictDeleteProperty,
          factory->NewNumberFromUint(actual_new_len - 1), array));
    } else {
      info.GetReturnValue().Set(false);
    }
  } else {
    info.GetReturnValue().Set(true);
  }
}

Handle<AccessorInfo> Accessors::MakeArrayLengthInfo(Isolate* isolate) {
  return MakeAccessor(isolate, isolate->factory()->length_string(),
                      &ArrayLengthGetter, &ArrayLengthSetter);
}

//
// Accessors::ModuleNamespaceEntry
//

void Accessors::ModuleNamespaceEntryGetter(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  HandleScope scope(isolate);
  Tagged<JSModuleNamespace> holder =
      Cast<JSModuleNamespace>(*Utils::OpenDirectHandle(*info.Holder()));
  Handle<Object> result;
  if (holder->GetExport(isolate, Cast<String>(Utils::OpenHandle(*name)))
          .ToHandle(&result)) {
    info.GetReturnValue().Set(Utils::ToLocal(result));
  }
}

void Accessors::ModuleNamespaceEntrySetter(
    v8::Local<v8::Name> name, v8::Local<v8::Value> val,
    const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  HandleScope scope(isolate);
  Factory* factory = isolate->factory();
  Handle<JSModuleNamespace> holder =
      Cast<JSModuleNamespace>(Utils::OpenHandle(*info.Holder()));

  if (info.ShouldThrowOnError()) {
    isolate->Throw(*factory->NewTypeError(
        MessageTemplate::kStrictReadOnlyProperty, Utils::OpenHandle(*name),
        i::Object::TypeOf(isolate, holder), holder));
  } else {
    info.GetReturnValue().Set(false);
  }
}

Handle<AccessorInfo> Accessors::MakeModuleNamespaceEntryInfo(
    Isolate* isolate, Handle<String> name) {
  return MakeAccessor(isolate, name, &ModuleNamespaceEntryGetter,
                      &ModuleNamespaceEntrySetter);
}

//
// Accessors::StringLength
//

void Accessors::StringLengthGetter(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  RCS_SCOPE(isolate, RuntimeCallCounterId::kStringLengthGetter);
  DisallowGarbageCollection no_gc;
  HandleScope scope(isolate);

  // We have a slight impedance mismatch between the external API and the way we
  // use callbacks internally: Externally, callbacks can only be used with
  // v8::Object, but internally we have callbacks on entities which are higher
  // in the hierarchy, in this case for String values.

  Tagged<Object> value =
      *Utils::OpenDirectHandle(*v8::Local<v8::Value>(info.This()));
  if (!IsString(value)) {
    // Not a string value. That means that we either got a String wrapper or
    // a Value with a String wrapper in its prototype chain.
    value = Cast<JSPrimitiveWrapper>(*Utils::OpenDirectHandle(*info.Holder()))
                ->value();
  }
  Tagged<Object> result = Smi::FromInt(Cast<String>(value)->length());
  info.GetReturnValue().Set(Utils::ToLocal(Handle<Object>(result, isolate)));
}

Handle<AccessorInfo> Accessors::MakeStringLengthInfo(Isolate* isolate) {
  return MakeAccessor(isolate, isolate->factory()->length_string(),
                      &StringLengthGetter, nullptr);
}

//
// Accessors::FunctionPrototype
//

static Handle<Object> GetFunctionPrototype(Isolate* isolate,
                                           DirectHandle<JSFunction> function) {
  if (!function->has_prototype()) {
    // We lazily allocate .prototype for functions, which confuses debug
    // evaluate which assumes we can write to temporary objects we allocated
    // during evaluation. We err on the side of caution here and prevent the
    // newly allocated prototype from going into the temporary objects set,
    // which means writes to it will be considered a side effect.
    DisableTemporaryObjectTracking no_temp_tracking(isolate->debug());
    Handle<JSObject> proto = isolate->factory()->NewFunctionPrototype(function);
    JSFunction::SetPrototype(function, proto);
  }
  return Handle<Object>(function->prototype(), isolate);
}

void Accessors::FunctionPrototypeGetter(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  RCS_SCOPE(isolate, RuntimeCallCounterId::kFunctionPrototypeGetter);
  HandleScope scope(isolate);
  DirectHandle<JSFunction> function =
      Cast<JSFunction>(Utils::OpenDirectHandle(*info.Holder()));
  DCHECK(function->has_prototype_property());
  Handle<Object> result = GetFunctionPrototype(isolate, function);
  info.GetReturnValue().Set(Utils::ToLocal(result));
}

void Accessors::FunctionPrototypeSetter(
    v8::Local<v8::Name> name, v8::Local<v8::Value> val,
    const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  RCS_SCOPE(isolate, RuntimeCallCounterId::kFunctionPrototypeSetter);
  HandleScope scope(isolate);
  Handle<Object> value = Utils::OpenHandle(*val);
  DirectHandle<JSFunction> object =
      Cast<JSFunction>(Utils::OpenDirectHandle(*info.Holder()));
  DCHECK(object->has_prototype_property());
  JSFunction::SetPrototype(object, value);
  info.GetReturnValue().Set(true);
}

Handle<AccessorInfo> Accessors::MakeFunctionPrototypeInfo(Isolate* isolate) {
  return MakeAccessor(isolate, isolate->factory()->prototype_string(),
                      &FunctionPrototypeGetter, &FunctionPrototypeSetter);
}

//
// Accessors::FunctionLength
//

void Accessors::FunctionLengthGetter(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  RCS_SCOPE(isolate, RuntimeCallCounterId::kFunctionLengthGetter);
  HandleScope scope(isolate);
  auto function = Cast<JSFunction>(Utils::OpenDirectHandle(*info.Holder()));
  int length = function->length();
  Handle<Object> result(Smi::FromInt(length), isolate);
  info.GetReturnValue().Set(Utils::ToLocal(result));
}

Handle<AccessorInfo> Accessors::MakeFunctionLengthInfo(Isolate* isolate) {
  return MakeAccessor(isolate, isolate->factory()->length_string(),
                      &FunctionLengthGetter, &ReconfigureToDataProperty);
}

//
// Accessors::FunctionName
//

void Accessors::FunctionNameGetter(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  HandleScope scope(isolate);
  auto function = Cast<JSFunction>(Utils::OpenDirectHandle(*info.Holder()));
  Handle<Object> result = JSFunction::GetName(isolate, function);
  info.GetReturnValue().Set(Utils::ToLocal(result));
}

Handle<AccessorInfo> Accessors::MakeFunctionNameInfo(Isolate* isolate) {
  return MakeAccessor(isolate, isolate->factory()->name_string(),
                      &FunctionNameGetter, &ReconfigureToDataProperty);
}

//
// Accessors::FunctionArguments
//

namespace {

Handle<JSObject> ArgumentsFromDeoptInfo(JavaScriptFrame* frame,
                                        int inlined_frame_index) {
  Isolate* isolate = frame->isolate();
  Factory* factory = isolate->factory();

  TranslatedState translated_values(frame);
  translated_values.Prepare(frame->fp());

  int argument_count = 0;
  TranslatedFrame* translated_frame =
      translated_values.GetArgumentsInfoFromJSFrameIndex(inlined_frame_index,
                                                         &argument_count);
  TranslatedFrame::iterator iter = translated_frame->begin();

  // Materialize the function.
  bool should_deoptimize = iter->IsMaterializedObject();
  Handle<JSFunction> function = Cast<JSFunction>(iter->GetValue());
  iter++;

  // Skip the receiver.
  iter++;
  argument_count--;

  Handle<JSObject> arguments =
      factory->NewArgumentsObject(function, argument_count);
  DirectHandle<FixedArray> array = factory->NewFixedArray(argument_count);
  for (int i = 0; i < argument_count; ++i) {
    // If we materialize any object, we should deoptimize the frame because we
    // might alias an object that was eliminated by escape analysis.
    should_deoptimize = should_deoptimize || iter->IsMaterializedObject();
    DirectHandle<Object> value = iter->GetValue();
    array->set(i, *value);
    iter++;
  }
  arguments->set_elements(*array);

  if (should_deoptimize) {
    translated_values.StoreMaterializedValuesAndDeopt(frame);
  }

  // Return the freshly allocated arguments object.
  return arguments;
}

int FindFunctionInFrame(JavaScriptFrame* frame,
                        DirectHandle<JSFunction> function) {
  std::vector<FrameSummary> frames;
  frame->Summarize(&frames);
  for (size_t i = frames.size(); i != 0; i--) {
    if (*frames[i - 1].AsJavaScript().function() == *function) {
      return static_cast<int>(i) - 1;
    }
  }
  return -1;
}

Handle<JSObject> GetFrameArguments(Isolate* isolate,
                                   JavaScriptStackFrameIterator* it,
                                   int function_index) {
  JavaScriptFrame* frame = it->frame();

  if (function_index > 0) {
    // The function in question was inlined.  Inlined functions have the
    // correct number of arguments and no allocated arguments object, so
    // we can construct a fresh one by interpreting the function's
    // deoptimization input data.
    return ArgumentsFromDeoptInfo(frame, function_index);
  }

  // Construct an arguments object mirror for the right frame and the underlying
  // function.
  const int length = frame->GetActualArgumentCount();
  Handle<JSFunction> function(frame->function(), isolate);
  Handle<JSObject> arguments =
      isolate->factory()->NewArgumentsObject(function, length);
  DirectHandle<FixedArray> array = isolate->factory()->NewFixedArray(length);

  // Copy the parameters to the arguments object.
  DCHECK(array->length() == length);
  for (int i = 0; i < length; i++) {
    Tagged<Object> value = frame->GetParameter(i);
    if (IsTheHole(value, isolate)) {
      // Generators currently use holes as dummy arguments when resuming.  We
      // must not leak those.
      DCHECK(IsResumableFunction(function->shared()->kind()));
      value = ReadOnlyRoots(isolate).undefined_value();
    }
    array->set(i, value);
  }
  arguments->set_elements(*array);

  // For optimized functions, the frame arguments may be outdated, so we should
  // update them with the deopt info, while keeping the length and extra
  // arguments from the actual frame.
  if (CodeKindCanDeoptimize(frame->LookupCode()->kind()) && length > 0) {
    DirectHandle<JSObject> arguments_from_deopt_info =
        ArgumentsFromDeoptInfo(frame, function_index);
    DirectHandle<FixedArray> elements_from_deopt_info(
        Cast<FixedArray>(arguments_from_deopt_info->elements()), isolate);
    int common_length = std::min(length, elements_from_deopt_info->length());
    for (int i = 0; i < common_length; i++) {
      array->set(i, elements_from_deopt_info->get(i));
    }
  }

  // Return the freshly allocated arguments object.
  return arguments;
}

}  // namespace

Handle<JSObject> Accessors::FunctionGetArguments(JavaScriptFrame* frame,
                                                 int inlined_jsframe_index) {
  Isolate* isolate = frame->isolate();
  Address requested_frame_fp = frame->fp();
  // Forward a frame iterator to the requested frame. This is needed because we
  // potentially need for advance it to the inlined arguments frame later.
  for (JavaScriptStackFrameIterator it(isolate); !it.done(); it.Advance()) {
    if (it.frame()->fp() != requested_frame_fp) continue;
    return GetFrameArguments(isolate, &it, inlined_jsframe_index);
  }
  UNREACHABLE();  // Requested frame not found.
}

void Accessors::FunctionArgumentsGetter(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  isolate->CountUsage(v8::Isolate::kFunctionPrototypeArguments);
  HandleScope scope(isolate);
  auto function = Cast<JSFunction>(Utils::OpenDirectHandle(*info.Holder()));
  Handle<Object> result = isolate->factory()->null_value();
  if (!function->shared()->native()) {
    // Find the top invocation of the function by traversing frames.
    for (JavaScriptStackFrameIterator it(isolate); !it.done(); it.Advance()) {
      JavaScriptFrame* frame = it.frame();
      int function_index = FindFunctionInFrame(frame, function);
      if (function_index >= 0) {
        result = GetFrameArguments(isolate, &it, function_index);
        break;
      }
    }
  }
  info.GetReturnValue().Set(Utils::ToLocal(result));
}

Handle<AccessorInfo> Accessors::MakeFunctionArgumentsInfo(Isolate* isolate) {
  return MakeAccessor(isolate, isolate->factory()->arguments_string(),
                      &FunctionArgumentsGetter, nullptr);
}

//
// Accessors::FunctionCaller
//

static inline bool AllowAccessToFunction(Tagged<Context> current_context,
                                         Tagged<JSFunction> function) {
  return current_context->HasSameSecurityTokenAs(function->context());
}

class FrameFunctionIterator {
 public:
  explicit FrameFunctionIterator(Isolate* isolate)
      : isolate_(isolate), frame_iterator_(isolate), inlined_frame_index_(-1) {
    GetFrames();
  }

  // Iterate through functions until the first occurrence of 'function'.
  // Returns true if one is found, and false if the iterator ends before.
  bool Find(Handle<JSFunction> function) {
    do {
      if (!next().ToHandle(&function_)) return false;
    } while (!function_.is_identical_to(function));
    return true;
  }

  // Iterate through functions until the next non-toplevel one is found.
  // Returns true if one is found, and false if the iterator ends before.
  bool FindNextNonTopLevel() {
    do {
      if (!next().ToHandle(&function_)) return false;
    } while (function_->shared()->is_toplevel());
    return true;
  }

  // Iterate through function until the first native or user-provided function
  // is found. Functions not defined in user-provided scripts are not visible
  // unless directly exposed, in which case the native flag is set on them.
  // Returns true if one is found, and false if the iterator ends before.
  bool FindFirstNativeOrUserJavaScript() {
    while (!function_->shared()->native() &&
           !function_->shared()->IsUserJavaScript()) {
      if (!next().ToHandle(&function_)) return false;
    }
    return true;
  }

  // In case of inlined frames the function could have been materialized from
  // deoptimization information. If that is the case we need to make sure that
  // subsequent call will see the same function, since we are about to hand out
  // the value to JavaScript. Make sure to store the materialized value and
  // trigger a deoptimization of the underlying frame.
  Handle<JSFunction> MaterializeFunction() {
    if (inlined_frame_index_ == 0) return function_;

    JavaScriptFrame* frame = frame_iterator_.frame();
    TranslatedState translated_values(frame);
    translated_values.Prepare(frame->fp());

    TranslatedFrame* translated_frame =
        translated_values.GetFrameFromJSFrameIndex(inlined_frame_index_);
    TranslatedFrame::iterator iter = translated_frame->begin();

    // First value is the function.
    bool should_deoptimize = iter->IsMaterializedObject();
    Handle<Object> value = iter->GetValue();
    if (should_deoptimize) {
      translated_values.StoreMaterializedValuesAndDeopt(frame);
    }

    return Cast<JSFunction>(value);
  }

 private:
  MaybeHandle<JSFunction> next() {
    while (true) {
      if (inlined_frame_index_ <= 0) {
        if (!frame_iterator_.done()) {
          frame_iterator_.Advance();
          frames_.clear();
          inlined_frame_index_ = -1;
          GetFrames();
        }
        if (inlined_frame_index_ == -1) return MaybeHandle<JSFunction>();
      }

      --inlined_frame_index_;
      Handle<JSFunction> next_function =
          frames_[inlined_frame_index_].AsJavaScript().function();
      // Skip functions from other origins.
      if (!AllowAccessToFunction(isolate_->context(), *next_function)) continue;
      return next_function;
    }
  }
  void GetFrames() {
    DCHECK_EQ(-1, inlined_frame_index_);
    if (frame_iterator_.done()) return;
    JavaScriptFrame* frame = frame_iterator_.frame();
    frame->Summarize(&frames_);
    inlined_frame_index_ = static_cast<int>(frames_.size());
    DCHECK_LT(0, inlined_frame_index_);
  }
  Isolate* isolate_;
  Handle<JSFunction> function_;
  JavaScriptStackFrameIterator frame_iterator_;
  std::vector<FrameSummary> frames_;
  int inlined_frame_index_;
};

MaybeHandle<JSFunction> FindCaller(Isolate* isolate,
                                   Handle<JSFunction> function) {
  FrameFunctionIterator it(isolate);
  if (function->shared()->native()) {
    return MaybeHandle<JSFunction>();
  }
  // Find the function from the frames. Return null in case no frame
  // corresponding to the given function was found.
  if (!it.Find(function)) {
    return MaybeHandle<JSFunction>();
  }
  // Find previously called non-toplevel function.
  if (!it.FindNextNonTopLevel()) {
    return MaybeHandle<JSFunction>();
  }
  // Find the first user-land JavaScript function (or the entry point into
  // native JavaScript builtins in case such a builtin was the caller).
  if (!it.FindFirstNativeOrUserJavaScript()) {
    return MaybeHandle<JSFunction>();
  }

  // Materialize the function that the iterator is currently sitting on. Note
  // that this might trigger deoptimization in case the function was actually
  // materialized. Identity of the function must be preserved because we are
  // going to return it to JavaScript after this point.
  Handle<JSFunction> caller = it.MaterializeFunction();

  // Censor if the caller is not a sloppy mode function.
  // Change from ES5, which used to throw, see:
  // https://bugs.ecmascript.org/show_bug.cgi?id=310
  if (is_strict(caller->shared()->language_mode())) {
    return MaybeHandle<JSFunction>();
  }
  // Don't return caller from another security context.
  if (!AllowAccessToFunction(isolate->context(), *caller)) {
    return MaybeHandle<JSFunction>();
  }
  return caller;
}

void Accessors::FunctionCallerGetter(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  isolate->CountUsage(v8::Isolate::kFunctionPrototypeCaller);
  HandleScope scope(isolate);
  Handle<JSFunction> function =
      Cast<JSFunction>(Utils::OpenHandle(*info.Holder()));
  Handle<Object> result;
  MaybeHandle<JSFunction> maybe_caller;
  maybe_caller = FindCaller(isolate, function);
  Handle<JSFunction> caller;
  // We don't support caller access with correctness fuzzing.
  if (!v8_flags.correctness_fuzzer_suppressions &&
      maybe_caller.ToHandle(&caller)) {
    result = caller;
  } else {
    result = isolate->factory()->null_value();
  }
  info.GetReturnValue().Set(Utils::ToLocal(result));
}

Handle<AccessorInfo> Accessors::MakeFunctionCallerInfo(Isolate* isolate) {
  return MakeAccessor(isolate, isolate->factory()->caller_string(),
                      &FunctionCallerGetter, nullptr);
}

//
// Accessors::BoundFunctionLength
//

void Accessors::BoundFunctionLengthGetter(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  RCS_SCOPE(isolate, RuntimeCallCounterId::kBoundFunctionLengthGetter);
  HandleScope scope(isolate);
  DirectHandle<JSBoundFunction> function =
      Cast<JSBoundFunction>(Utils::OpenHandle(*info.Holder()));

  int length = 0;
  if (!JSBoundFunction::GetLength(isolate, function).To(&length)) {
    return;
  }
  Handle<Object> result(Smi::FromInt(length), isolate);
  info.GetReturnValue().Set(Utils::ToLocal(result));
}

Handle<AccessorInfo> Accessors::MakeBoundFunctionLengthInfo(Isolate* isolate) {
  return MakeAccessor(isolate, isolate->factory()->length_string(),
                      &BoundFunctionLengthGetter, &ReconfigureToDataProperty);
}

//
// Accessors::BoundFunctionName
//

void Accessors::BoundFunctionNameGetter(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  RCS_SCOPE(isolate, RuntimeCallCounterId::kBoundFunctionNameGetter);
  HandleScope scope(isolate);
  DirectHandle<JSBoundFunction> function =
      Cast<JSBoundFunction>(Utils::OpenHandle(*info.Holder()));
  Handle<Object> result;
  if (!JSBoundFunction::GetName(isolate, function).ToHandle(&result)) {
    return;
  }
  info.GetReturnValue().Set(Utils::ToLocal(result));
}

Handle<AccessorInfo> Accessors::MakeBoundFunctionNameInfo(Isolate* isolate) {
  return MakeAccessor(isolate, isolate->factory()->name_string(),
                      &BoundFunctionNameGetter, &ReconfigureToDataProperty);
}

//
// Accessors::WrappedFunctionLength
//

void Accessors::WrappedFunctionLengthGetter(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  RCS_SCOPE(isolate, RuntimeCallCounterId::kBoundFunctionLengthGetter);
  HandleScope scope(isolate);
  auto function =
      Cast<JSWrappedFunction>(Utils::OpenDirectHandle(*info.Holder()));

  int length = 0;
  if (!JSWrappedFunction::GetLength(isolate, function).To(&length)) {
    return;
  }
  Handle<Object> result(Smi::FromInt(length), isolate);
  info.GetReturnValue().Set(Utils::ToLocal(result));
}

Handle<AccessorInfo> Accessors::MakeWrappedFunctionLengthInfo(
    Isolate* isolate) {
  return MakeAccessor(isolate, isolate->factory()->length_string(),
                      &WrappedFunctionLengthGetter, &ReconfigureToDataProperty);
}

//
// Accessors::ValueUnavailable
//

void Accessors::ValueUnavailableGetter(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  Isolate* isolate = reinterpret_cast<Isolate*>(info.GetIsolate());
  HandleScope scope(isolate);
  isolate->Throw(*isolate->factory()->NewReferenceError(
      MessageTemplate::kAccessedUnavailableVariable, Utils::OpenHandle(*name)));
}

Handle<AccessorInfo> Accessors::MakeValueUnavailableInfo(Isolate* isolate) {
  return MakeAccessor(isolate, isolate->factory()->empty_string(),
                      &ValueUnavailableGetter, &ReconfigureToDataProperty);
}

//
// Accessors::WrappedFunctionName
//

void Accessors::WrappedFunctionNameGetter(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  i::Isolate* isolate = reinterpret_cast<i::Isolate*>(info.GetIsolate());
  RCS_SCOPE(isolate, RuntimeCallCounterId::kWrappedFunctionNameGetter);
  HandleScope scope(isolate);
  auto function =
      Cast<JSWrappedFunction>(Utils::OpenDirectHandle(*info.Holder()));
  Handle<Object> result;
  if (!JSWrappedFunction::GetName(isolate, function).ToHandle(&result)) {
    return;
  }
  info.GetReturnValue().Set(Utils::ToLocal(result));
}

Handle<AccessorInfo> Accessors::MakeWrappedFunctionNameInfo(Isolate* isolate) {
  return MakeAccessor(isolate, isolate->factory()->name_string(),
                      &WrappedFunctionNameGetter, &ReconfigureToDataProperty);
}

// Allow usages of v8::PropertyCallbackInfo<T>::Holder() for now.
// TODO(https://crbug.com/333672197): remove.
END_ALLOW_USE_DEPRECATED()

//
// Accessors::ErrorStack
//

void Accessors::ErrorStackGetter(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  Isolate* isolate = reinterpret_cast<Isolate*>(info.GetIsolate());
  HandleScope scope(isolate);
  Handle<Object> formatted_stack = isolate->factory()->undefined_value();
  Handle<JSReceiver> maybe_error_object = Utils::OpenHandle(*info.This());
  if (IsJSObject(*maybe_error_object)) {
    if (!ErrorUtils::GetFormattedStack(isolate,
                                       Cast<JSObject>(maybe_error_object))
             .ToHandle(&formatted_stack)) {
      return;
    }
  }
  v8::Local<v8::Value> result = Utils::ToLocal(formatted_stack);
  CHECK(result->IsValue());
  info.GetReturnValue().Set(result);
}

void Accessors::ErrorStackSetter(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  Isolate* isolate = reinterpret_cast<Isolate*>(info.GetIsolate());
  HandleScope scope(isolate);
  Handle<JSReceiver> maybe_error_object = Utils::OpenHandle(*info.This());
  if (IsJSObject(*maybe_error_object)) {
    v8::Local<v8::Value> value = info[0];
    ErrorUtils::SetFormattedStack(isolate, Cast<JSObject>(maybe_error_object),
                                  Utils::OpenHandle(*value));
  }
}

}  // namespace internal
}  // namespace v8
```