Response: The user wants a summary of the C++ code in `v8/test/cctest/test-api-interceptors.cc`.
The file seems to define various C++ functions and classes related to V8's API, specifically focusing on interceptors.

**Plan:**
1. Identify the core purpose of the file.
2. List the key C++ functions and their roles.
3. Determine if the functionality is related to JavaScript.
4. If related, provide a JavaScript example demonstrating the concept.
这个C++代码文件(`v8/test/cctest/test-api-interceptors.cc`)是V8 JavaScript引擎的测试代码，**主要用于测试V8 API中关于属性访问拦截器（interceptors）的功能。**

简单来说，拦截器允许C++代码介入并自定义JavaScript对象属性的读取、写入、查询、删除等操作的行为。

以下是代码中一些关键功能的归纳：

*   **定义了多种拦截器回调函数：**  例如 `Return239Callback`, `EmptyInterceptorGetter`, `EmptyInterceptorSetter`, `InterceptorGetter`, `InterceptorSetter`, `GenericInterceptorGetter`, `GenericInterceptorSetter` 等。这些函数模拟了不同的拦截行为，例如返回固定值、执行特定逻辑、或者根据属性名进行拦截。
*   **测试不同类型的拦截器：** 代码中使用了 `v8::NamedPropertyHandlerConfiguration` 来设置对象的属性访问处理器，包括 getter、setter、query、deleter、enumerator 和 definer。
*   **测试拦截器与JavaScript的交互：**  通过 `CompileRun` 函数执行JavaScript代码，并验证在设置了拦截器的情况下，JavaScript代码的执行结果是否符合预期。
*   **测试性能优化相关的拦截器场景：** 例如，代码中有 `InterceptorLoadICGetter` 和相关的测试用例，用于测试JIT编译器如何优化带有拦截器的属性访问。
*   **测试各种边界情况和错误处理：** 例如，测试当拦截器尝试修改只读属性时会发生什么。

**与JavaScript功能的关系以及JavaScript示例：**

属性访问拦截器在JavaScript层面并没有直接对应的语法结构，它是V8引擎提供的一种底层的C++ API，用于扩展和自定义JavaScript对象的行为。开发者可以通过C++代码定义拦截器，然后在JavaScript中使用这些带有特殊行为的对象。

**JavaScript示例（概念性）：**

假设在C++中，我们定义了一个带有拦截器的模板，当访问一个名为 `interceptedProperty` 的属性时，拦截器会返回固定的值 100。

```javascript
// 假设 'myObject' 是一个基于带有拦截器的模板创建的 JavaScript 对象

console.log(myObject.interceptedProperty); // 在 C++ 拦截器的作用下，输出 100

myObject.interceptedProperty = 50; //  setter 拦截器也可能介入这个操作

console.log(myObject.interceptedProperty); // 输出仍然可能是 100，取决于 setter 拦截器的实现
```

**总结来说，这个C++文件是用来测试V8引擎的属性访问拦截器机制是否正常工作，确保C++代码能够按照预期地干预和自定义JavaScript对象的属性访问行为。**

Prompt: 
```
这是目录为v8/test/cctest/test-api-interceptors.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include <optional>

#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "src/codegen/compilation-cache.h"
#include "src/execution/execution.h"
#include "src/objects/objects-inl.h"
#include "src/objects/objects.h"
#include "src/runtime/runtime.h"
#include "src/strings/unicode-inl.h"
#include "test/cctest/heap/heap-utils.h"
#include "test/cctest/test-api.h"

using ::v8::Context;
using ::v8::Function;
using ::v8::FunctionTemplate;
using ::v8::Local;
using ::v8::Name;
using ::v8::Object;
using ::v8::ObjectTemplate;
using ::v8::Script;
using ::v8::String;
using ::v8::Symbol;
using ::v8::Value;

namespace {

void Returns42(const v8::FunctionCallbackInfo<v8::Value>& info) {
  info.GetReturnValue().Set(42);
}

void Return239Callback(Local<Name> name,
                       const v8::PropertyCallbackInfo<Value>& info) {
  ApiTestFuzzer::Fuzz();
  CheckReturnValue(info, FUNCTION_ADDR(Return239Callback));
  info.GetReturnValue().Set(v8_str("bad value"));
  info.GetReturnValue().Set(v8_num(239));
}

v8::Intercepted EmptyInterceptorGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  return v8::Intercepted::kNo;
}

v8::Intercepted EmptyInterceptorSetter(
    Local<Name> name, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  return v8::Intercepted::kNo;
}

v8::Intercepted EmptyInterceptorQuery(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  return v8::Intercepted::kNo;
}

v8::Intercepted EmptyInterceptorDeleter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  return v8::Intercepted::kNo;
}

void EmptyInterceptorEnumerator(
    const v8::PropertyCallbackInfo<v8::Array>& info) {}

v8::Intercepted EmptyInterceptorDefinerWithSideEffect(
    Local<Name> name, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  ApiTestFuzzer::Fuzz();
  v8::Local<v8::Value> result = CompileRun("interceptor_definer_side_effect()");
  if (!result->IsNull()) {
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

void SimpleGetterImpl(Local<String> name_str,
                      const v8::FunctionCallbackInfo<v8::Value>& info) {
  Local<Object> self = info.This();
  info.GetReturnValue().Set(
      self->Get(
              info.GetIsolate()->GetCurrentContext(),
              String::Concat(info.GetIsolate(), v8_str("accessor_"), name_str))
          .ToLocalChecked());
}

void SimpleSetterImpl(Local<String> name_str,
                      const v8::FunctionCallbackInfo<v8::Value>& info) {
  Local<Object> self = info.This();
  Local<Value> value = info[0];
  self->Set(info.GetIsolate()->GetCurrentContext(),
            String::Concat(info.GetIsolate(), v8_str("accessor_"), name_str),
            value)
      .FromJust();
}

void SimpleGetterCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  Local<String> name_str = args.Data().As<String>();
  SimpleGetterImpl(name_str, args);
}

void SimpleSetterCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  Local<String> name_str = info.Data().As<String>();
  SimpleSetterImpl(name_str, info);
}

void SymbolGetterCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  Local<Name> name = info.Data().As<Name>();
  CHECK(name->IsSymbol());
  v8::Isolate* isolate = info.GetIsolate();
  Local<Symbol> sym = name.As<Symbol>();
  if (sym->Description(isolate)->IsUndefined()) return;
  SimpleGetterImpl(sym->Description(isolate).As<String>(), info);
}

void SymbolSetterCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  Local<Name> name = info.Data().As<Name>();
  CHECK(name->IsSymbol());
  v8::Isolate* isolate = info.GetIsolate();
  Local<Symbol> sym = name.As<Symbol>();
  if (sym->Description(isolate)->IsUndefined()) return;
  SimpleSetterImpl(sym->Description(isolate).As<String>(), info);
}

v8::Intercepted InterceptorGetter(
    Local<Name> generic_name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  if (generic_name->IsSymbol()) return v8::Intercepted::kNo;
  Local<String> name = generic_name.As<String>();
  String::Utf8Value utf8(info.GetIsolate(), name);
  char* name_str = *utf8;
  char prefix[] = "interceptor_";
  int i;
  for (i = 0; name_str[i] && prefix[i]; ++i) {
    if (name_str[i] != prefix[i]) return v8::Intercepted::kNo;
  }
  Local<Object> self = info.This().As<Object>();
  info.GetReturnValue().Set(
      self->GetPrivate(
              info.GetIsolate()->GetCurrentContext(),
              v8::Private::ForApi(info.GetIsolate(), v8_str(name_str + i)))
          .ToLocalChecked());
  return v8::Intercepted::kYes;
}

v8::Intercepted InterceptorSetter(Local<Name> generic_name, Local<Value> value,
                                  const v8::PropertyCallbackInfo<void>& info) {
  if (generic_name->IsSymbol()) return v8::Intercepted::kNo;
  Local<String> name = generic_name.As<String>();
  // Intercept accesses that set certain integer values, for which the name does
  // not start with 'accessor_'.
  String::Utf8Value utf8(info.GetIsolate(), name);
  char* name_str = *utf8;
  char prefix[] = "accessor_";
  int i;
  for (i = 0; name_str[i] && prefix[i]; ++i) {
    if (name_str[i] != prefix[i]) break;
  }
  if (!prefix[i]) return v8::Intercepted::kNo;

  Local<Context> context = info.GetIsolate()->GetCurrentContext();
  if (value->IsInt32() && value->Int32Value(context).FromJust() < 10000) {
    Local<Object> self = info.This().As<Object>();
    Local<v8::Private> symbol = v8::Private::ForApi(info.GetIsolate(), name);
    self->SetPrivate(context, symbol, value).FromJust();
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted GenericInterceptorGetter(
    Local<Name> generic_name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  Local<String> str;
  if (generic_name->IsSymbol()) {
    Local<Value> name = generic_name.As<Symbol>()->Description(isolate);
    if (name->IsUndefined()) return v8::Intercepted::kNo;
    str = String::Concat(info.GetIsolate(), v8_str("_sym_"), name.As<String>());
  } else {
    Local<String> name = generic_name.As<String>();
    String::Utf8Value utf8(info.GetIsolate(), name);
    char* name_str = *utf8;
    if (*name_str == '_') return v8::Intercepted::kNo;
    str = String::Concat(info.GetIsolate(), v8_str("_str_"), name);
  }

  Local<Object> self = info.This().As<Object>();
  info.GetReturnValue().Set(
      self->Get(info.GetIsolate()->GetCurrentContext(), str).ToLocalChecked());
  return v8::Intercepted::kYes;
}

v8::Intercepted GenericInterceptorSetter(
    Local<Name> generic_name, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  Local<String> str;
  if (generic_name->IsSymbol()) {
    Local<Value> name = generic_name.As<Symbol>()->Description(isolate);
    if (name->IsUndefined()) return v8::Intercepted::kNo;
    str = String::Concat(info.GetIsolate(), v8_str("_sym_"), name.As<String>());
  } else {
    Local<String> name = generic_name.As<String>();
    String::Utf8Value utf8(info.GetIsolate(), name);
    char* name_str = *utf8;
    if (*name_str == '_') return v8::Intercepted::kNo;
    str = String::Concat(info.GetIsolate(), v8_str("_str_"), name);
  }

  Local<Object> self = info.This().As<Object>();
  self->Set(info.GetIsolate()->GetCurrentContext(), str, value).FromJust();
  return v8::Intercepted::kYes;
}

void AddAccessor(v8::Isolate* isolate, Local<FunctionTemplate> templ,
                 Local<Name> name, v8::FunctionCallback getter,
                 v8::FunctionCallback setter) {
  Local<FunctionTemplate> getter_templ =
      FunctionTemplate::New(isolate, getter, name);
  Local<FunctionTemplate> setter_templ =
      FunctionTemplate::New(isolate, setter, name);

  templ->PrototypeTemplate()->SetAccessorProperty(name, getter_templ,
                                                  setter_templ);
}

void AddStringOnlyInterceptor(Local<FunctionTemplate> templ,
                              v8::NamedPropertyGetterCallback getter,
                              v8::NamedPropertySetterCallback setter) {
  templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
      getter, setter, nullptr, nullptr, nullptr, Local<v8::Value>(),
      v8::PropertyHandlerFlags::kOnlyInterceptStrings));
}

void AddInterceptor(Local<FunctionTemplate> templ,
                    v8::NamedPropertyGetterCallback getter,
                    v8::NamedPropertySetterCallback setter) {
  templ->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(getter, setter));
}

v8::Global<v8::Object> bottom_global;

v8::Intercepted CheckThisIndexedPropertyHandler(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisIndexedPropertyHandler));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisNamedPropertyHandler(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisNamedPropertyHandler));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisIndexedPropertyDefiner(
    uint32_t index, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisIndexedPropertyDefiner));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisNamedPropertyDefiner(
    Local<Name> property, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisNamedPropertyDefiner));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisIndexedPropertySetter(
    uint32_t index, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisIndexedPropertySetter));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisNamedPropertySetter(
    Local<Name> property, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisNamedPropertySetter));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisIndexedPropertyDescriptor(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisIndexedPropertyDescriptor));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisNamedPropertyDescriptor(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisNamedPropertyDescriptor));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisIndexedPropertyQuery(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisIndexedPropertyQuery));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisNamedPropertyQuery(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisNamedPropertyQuery));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisIndexedPropertyDeleter(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisIndexedPropertyDeleter));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

v8::Intercepted CheckThisNamedPropertyDeleter(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisNamedPropertyDeleter));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
  return v8::Intercepted::kNo;
}

void CheckThisIndexedPropertyEnumerator(
    const v8::PropertyCallbackInfo<v8::Array>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisIndexedPropertyEnumerator));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
}


void CheckThisNamedPropertyEnumerator(
    const v8::PropertyCallbackInfo<v8::Array>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CheckReturnValue(info, FUNCTION_ADDR(CheckThisNamedPropertyEnumerator));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(), bottom_global.Get(isolate))
            .FromJust());
}


int echo_named_call_count;

v8::Intercepted EchoNamedProperty(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  CHECK(v8_str("data")
            ->Equals(info.GetIsolate()->GetCurrentContext(), info.Data())
            .FromJust());
  echo_named_call_count++;
  info.GetReturnValue().Set(name);
  return v8::Intercepted::kYes;
}

v8::Intercepted InterceptorHasOwnPropertyGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  return v8::Intercepted::kNo;
}

v8::Intercepted InterceptorHasOwnPropertyGetterGC(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  i::heap::InvokeMajorGC(CcTest::heap());
  return v8::Intercepted::kNo;
}

int query_counter_int = 0;

v8::Intercepted QueryCallback(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  query_counter_int++;
  return v8::Intercepted::kNo;
}

}  // namespace

// Examples that show when the query callback is triggered.
THREADED_TEST(QueryInterceptor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(nullptr, nullptr, QueryCallback));
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                            .ToLocalChecked()
                                            ->NewInstance(env.local())
                                            .ToLocalChecked())
      .FromJust();
  CHECK_EQ(0, query_counter_int);
  v8::Local<Value> result =
      v8_compile("Object.getOwnPropertyDescriptor(obj, 'x');")
          ->Run(env.local())
          .ToLocalChecked();
  CHECK_EQ(1, query_counter_int);
  CHECK_EQ(v8::PropertyAttribute::None,
           static_cast<v8::PropertyAttribute>(
               result->Int32Value(env.local()).FromJust()));

  v8_compile("Object.defineProperty(obj, 'not_enum', {value: 17});")
      ->Run(env.local())
      .ToLocalChecked();
  CHECK_EQ(2, query_counter_int);

  v8_compile(
      "Object.defineProperty(obj, 'enum', {value: 17, enumerable: true, "
      "writable: true});")
      ->Run(env.local())
      .ToLocalChecked();
  CHECK_EQ(3, query_counter_int);

  CHECK(v8_compile("obj.propertyIsEnumerable('enum');")
            ->Run(env.local())
            .ToLocalChecked()
            ->BooleanValue(isolate));
  CHECK_EQ(4, query_counter_int);

  CHECK(!v8_compile("obj.propertyIsEnumerable('not_enum');")
             ->Run(env.local())
             .ToLocalChecked()
             ->BooleanValue(isolate));
  CHECK_EQ(5, query_counter_int);

  CHECK(v8_compile("obj.hasOwnProperty('enum');")
            ->Run(env.local())
            .ToLocalChecked()
            ->BooleanValue(isolate));
  CHECK_EQ(5, query_counter_int);

  CHECK(v8_compile("obj.hasOwnProperty('not_enum');")
            ->Run(env.local())
            .ToLocalChecked()
            ->BooleanValue(isolate));
  CHECK_EQ(5, query_counter_int);

  CHECK(!v8_compile("obj.hasOwnProperty('x');")
             ->Run(env.local())
             .ToLocalChecked()
             ->BooleanValue(isolate));
  CHECK_EQ(6, query_counter_int);

  CHECK(!v8_compile("obj.propertyIsEnumerable('undef');")
             ->Run(env.local())
             .ToLocalChecked()
             ->BooleanValue(isolate));
  CHECK_EQ(7, query_counter_int);

  v8_compile("Object.defineProperty(obj, 'enum', {value: 42});")
      ->Run(env.local())
      .ToLocalChecked();
  CHECK_EQ(8, query_counter_int);

  v8_compile("Object.isFrozen('obj.x');")->Run(env.local()).ToLocalChecked();
  CHECK_EQ(8, query_counter_int);

  v8_compile("'x' in obj;")->Run(env.local()).ToLocalChecked();
  CHECK_EQ(9, query_counter_int);
}

namespace {

bool get_was_called = false;
bool set_was_called = false;

int set_was_called_counter = 0;

v8::Intercepted GetterCallback(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  get_was_called = true;
  return v8::Intercepted::kNo;
}

v8::Intercepted SetterCallback(Local<Name> property, Local<Value> value,
                               const v8::PropertyCallbackInfo<void>& info) {
  set_was_called = true;
  set_was_called_counter++;
  return v8::Intercepted::kNo;
}

v8::Intercepted InterceptingSetterCallback(
    Local<Name> property, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  return v8::Intercepted::kYes;
}

}  // namespace

// Check that get callback is called in defineProperty with accessor descriptor.
THREADED_TEST(DefinerCallbackAccessorInterceptor) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());
  templ->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(GetterCallback, SetterCallback));
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                            .ToLocalChecked()
                                            ->NewInstance(env.local())
                                            .ToLocalChecked())
      .FromJust();

  get_was_called = false;
  set_was_called = false;

  v8_compile("Object.defineProperty(obj, 'x', {set: function() {return 17;}});")
      ->Run(env.local())
      .ToLocalChecked();
  CHECK(get_was_called);
  CHECK(!set_was_called);
}

// Check that set callback is called for function declarations.
THREADED_TEST(SetterCallbackFunctionDeclarationInterceptor) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());

  v8::Local<ObjectTemplate> object_template = templ->InstanceTemplate();
  object_template->SetHandler(
      v8::NamedPropertyHandlerConfiguration(nullptr, SetterCallback));
  v8::Local<v8::Context> ctx =
      v8::Context::New(CcTest::isolate(), nullptr, object_template);

  set_was_called_counter = 0;

  // Declare function.
  v8::Local<v8::String> code = v8_str("function x() {return 42;}; x();");
  CHECK_EQ(42, v8::Script::Compile(ctx, code)
                   .ToLocalChecked()
                   ->Run(ctx)
                   .ToLocalChecked()
                   ->Int32Value(ctx)
                   .FromJust());
  CHECK_EQ(1, set_was_called_counter);

  // Redeclare function.
  code = v8_str("function x() {return 43;}; x();");
  CHECK_EQ(43, v8::Script::Compile(ctx, code)
                   .ToLocalChecked()
                   ->Run(ctx)
                   .ToLocalChecked()
                   ->Int32Value(ctx)
                   .FromJust());
  CHECK_EQ(2, set_was_called_counter);

  // Redefine function.
  code = v8_str("x = function() {return 44;}; x();");
  CHECK_EQ(44, v8::Script::Compile(ctx, code)
                   .ToLocalChecked()
                   ->Run(ctx)
                   .ToLocalChecked()
                   ->Int32Value(ctx)
                   .FromJust());
  CHECK_EQ(3, set_was_called_counter);
}

namespace {
int descriptor_was_called;

v8::Intercepted PropertyDescriptorCallback(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  // Intercept the callback and create some descriptor.
  descriptor_was_called++;
  const char* code =
      "var desc = {value: 5};"
      "desc;";
  Local<Value> descriptor = v8_compile(code)
                                ->Run(info.GetIsolate()->GetCurrentContext())
                                .ToLocalChecked();
  info.GetReturnValue().Set(descriptor);
  return v8::Intercepted::kYes;
}
}  // namespace

// Check that the descriptor callback is called on the global object.
THREADED_TEST(DescriptorCallbackOnGlobalObject) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());

  v8::Local<ObjectTemplate> object_template = templ->InstanceTemplate();
  object_template->SetHandler(v8::NamedPropertyHandlerConfiguration(
      nullptr, nullptr, PropertyDescriptorCallback, nullptr, nullptr, nullptr));
  v8::Local<v8::Context> ctx =
      v8::Context::New(CcTest::isolate(), nullptr, object_template);

  descriptor_was_called = 0;

  // Declare function.
  v8::Local<v8::String> code = v8_str(
      "var x = 42; var desc = Object.getOwnPropertyDescriptor(this, 'x'); "
      "desc.value;");
  CHECK_EQ(5, v8::Script::Compile(ctx, code)
                  .ToLocalChecked()
                  ->Run(ctx)
                  .ToLocalChecked()
                  ->Int32Value(ctx)
                  .FromJust());
  CHECK_EQ(1, descriptor_was_called);
}

namespace {
v8::Intercepted QueryCallbackSetDontDelete(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  info.GetReturnValue().Set(v8::DontDelete);
  return v8::Intercepted::kYes;
}

}  // namespace

// Regression for a Node.js test that fails in debug mode.
THREADED_TEST(InterceptorFunctionRedeclareWithQueryCallback) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());

  v8::Local<ObjectTemplate> object_template = templ->InstanceTemplate();
  object_template->SetHandler(v8::NamedPropertyHandlerConfiguration(
      nullptr, nullptr, QueryCallbackSetDontDelete));
  v8::Local<v8::Context> ctx =
      v8::Context::New(CcTest::isolate(), nullptr, object_template);

  // Declare and redeclare function.
  v8::Local<v8::String> code = v8_str(
      "function x() {return 42;};"
      "function x() {return 43;};");
  v8::Script::Compile(ctx, code).ToLocalChecked()->Run(ctx).ToLocalChecked();
}

// Regression test for chromium bug 656648.
// Do not crash on non-masking, intercepting setter callbacks.
THREADED_TEST(NonMaskingInterceptor) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());

  v8::Local<ObjectTemplate> object_template = templ->InstanceTemplate();
  object_template->SetHandler(v8::NamedPropertyHandlerConfiguration(
      nullptr, InterceptingSetterCallback, nullptr, nullptr, nullptr,
      Local<Value>(), v8::PropertyHandlerFlags::kNonMasking));
  v8::Local<v8::Context> ctx =
      v8::Context::New(CcTest::isolate(), nullptr, object_template);

  v8::Local<v8::String> code = v8_str("function x() {return 43;};");
  v8::Script::Compile(ctx, code).ToLocalChecked()->Run(ctx).ToLocalChecked();
}

// Check that function re-declarations throw if they are read-only.
THREADED_TEST(SetterCallbackFunctionDeclarationInterceptorThrow) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());

  v8::Local<ObjectTemplate> object_template = templ->InstanceTemplate();
  object_template->SetHandler(
      v8::NamedPropertyHandlerConfiguration(nullptr, SetterCallback));
  v8::Local<v8::Context> ctx =
      v8::Context::New(CcTest::isolate(), nullptr, object_template);

  set_was_called = false;

  v8::Local<v8::String> code = v8_str(
      "function x() {return 42;};"
      "Object.defineProperty(this, 'x', {"
      "configurable: false, "
      "writable: false});"
      "x();");
  CHECK_EQ(42, v8::Script::Compile(ctx, code)
                   .ToLocalChecked()
                   ->Run(ctx)
                   .ToLocalChecked()
                   ->Int32Value(ctx)
                   .FromJust());

  CHECK(set_was_called);

  v8::TryCatch try_catch(CcTest::isolate());
  set_was_called = false;

  // Redeclare function that is read-only.
  code = v8_str("function x() {return 43;};");
  CHECK(v8::Script::Compile(ctx, code).ToLocalChecked()->Run(ctx).IsEmpty());
  CHECK(try_catch.HasCaught());

  CHECK(!set_was_called);
}


namespace {

bool get_was_called_in_order = false;
bool define_was_called_in_order = false;

v8::Intercepted GetterCallbackOrder(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  get_was_called_in_order = true;
  CHECK(!define_was_called_in_order);
  info.GetReturnValue().Set(property);
  return v8::Intercepted::kYes;
}

v8::Intercepted DefinerCallbackOrder(
    Local<Name> property, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  // Get called before DefineProperty because we query the descriptor first.
  CHECK(get_was_called_in_order);
  define_was_called_in_order = true;
  return v8::Intercepted::kNo;
}

}  // namespace

// Check that getter callback is called before definer callback.
THREADED_TEST(DefinerCallbackGetAndDefine) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());
  templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
      GetterCallbackOrder, SetterCallback, nullptr, nullptr, nullptr,
      DefinerCallbackOrder));
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                            .ToLocalChecked()
                                            ->NewInstance(env.local())
                                            .ToLocalChecked())
      .FromJust();

  CHECK(!get_was_called_in_order);
  CHECK(!define_was_called_in_order);

  v8_compile("Object.defineProperty(obj, 'x', {set: function() {return 17;}});")
      ->Run(env.local())
      .ToLocalChecked();
  CHECK(get_was_called_in_order);
  CHECK(define_was_called_in_order);
}

namespace {  //  namespace for InObjectLiteralDefinitionWithInterceptor

// Workaround for no-snapshot builds: only intercept once Context::New() is
// done, otherwise we'll intercept
// bootstrapping like defining array on the global object.
bool context_is_done = false;
bool getter_callback_was_called = false;

v8::Intercepted ReturnUndefinedGetterCallback(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  if (context_is_done) {
    getter_callback_was_called = true;
    info.GetReturnValue().SetUndefined();
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

}  // namespace

// Check that an interceptor is not invoked during ES6 style definitions inside
// an object literal.
THREADED_TEST(InObjectLiteralDefinitionWithInterceptor) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;

  // Set up a context in which all global object definitions are intercepted.
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());
  v8::Local<ObjectTemplate> object_template = templ->InstanceTemplate();
  object_template->SetHandler(
      v8::NamedPropertyHandlerConfiguration(ReturnUndefinedGetterCallback));
  v8::Local<v8::Context> ctx =
      v8::Context::New(CcTest::isolate(), nullptr, object_template);

  context_is_done = true;

  // The interceptor returns undefined for any global object,
  // so setting a property on an object should throw.
  v8::Local<v8::String> code = v8_str("var o = {}; o.x = 5");
  {
    getter_callback_was_called = false;
    v8::TryCatch try_catch(CcTest::isolate());
    CHECK(v8::Script::Compile(ctx, code).ToLocalChecked()->Run(ctx).IsEmpty());
    CHECK(try_catch.HasCaught());
    CHECK(getter_callback_was_called);
  }

  // Defining a property in the object literal should not throw
  // because the interceptor is not invoked.
  {
    getter_callback_was_called = false;
    v8::TryCatch try_catch(CcTest::isolate());
    code = v8_str("var l = {x: 5};");
    CHECK(v8::Script::Compile(ctx, code)
              .ToLocalChecked()
              ->Run(ctx)
              .ToLocalChecked()
              ->IsUndefined());
    CHECK(!try_catch.HasCaught());
    CHECK(!getter_callback_was_called);
  }
}

THREADED_TEST(InterceptorHasOwnProperty) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<v8::FunctionTemplate> fun_templ = v8::FunctionTemplate::New(isolate);
  Local<v8::ObjectTemplate> instance_templ = fun_templ->InstanceTemplate();
  instance_templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorHasOwnPropertyGetter));
  Local<Function> function =
      fun_templ->GetFunction(context.local()).ToLocalChecked();
  context->Global()
      ->Set(context.local(), v8_str("constructor"), function)
      .FromJust();
  v8::Local<Value> value = CompileRun(
      "var o = new constructor();"
      "o.hasOwnProperty('ostehaps');");
  CHECK(!value->BooleanValue(isolate));
  value = CompileRun(
      "o.ostehaps = 42;"
      "o.hasOwnProperty('ostehaps');");
  CHECK(value->BooleanValue(isolate));
  value = CompileRun(
      "var p = new constructor();"
      "p.hasOwnProperty('ostehaps');");
  CHECK(!value->BooleanValue(isolate));
}


THREADED_TEST(InterceptorHasOwnPropertyCausingGC) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<v8::FunctionTemplate> fun_templ = v8::FunctionTemplate::New(isolate);
  Local<v8::ObjectTemplate> instance_templ = fun_templ->InstanceTemplate();
  instance_templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorHasOwnPropertyGetterGC));
  Local<Function> function =
      fun_templ->GetFunction(context.local()).ToLocalChecked();
  context->Global()
      ->Set(context.local(), v8_str("constructor"), function)
      .FromJust();
  // Let's first make some stuff so we can be sure to get a good GC.
  CompileRun(
      "function makestr(size) {"
      "  switch (size) {"
      "    case 1: return 'f';"
      "    case 2: return 'fo';"
      "    case 3: return 'foo';"
      "  }"
      "  return makestr(size >> 1) + makestr((size + 1) >> 1);"
      "}"
      "var x = makestr(12345);"
      "x = makestr(31415);"
      "x = makestr(23456);");
  v8::Local<Value> value = CompileRun(
      "var o = new constructor();"
      "o.__proto__ = new String(x);"
      "o.hasOwnProperty('ostehaps');");
  CHECK(!value->BooleanValue(isolate));
}

namespace {

void CheckInterceptorIC(v8::NamedPropertyGetterCallback getter,
                        v8::NamedPropertySetterCallback setter,
                        v8::NamedPropertyQueryCallback query,
                        v8::NamedPropertyDefinerCallback definer,
                        v8::PropertyHandlerFlags flags, const char* source,
                        std::optional<int> expected) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
      getter, setter, query, nullptr /* deleter */, nullptr /* enumerator */,
      definer, nullptr /* descriptor */, v8_str("data"), flags));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<Value> value = CompileRun(source);
  if (expected) {
    CHECK_EQ(*expected, value->Int32Value(context.local()).FromJust());
  } else {
    CHECK(value.IsEmpty());
  }
}

void CheckInterceptorIC(v8::NamedPropertyGetterCallback getter,
                        v8::NamedPropertyQueryCallback query,
                        const char* source, std::optional<int> expected) {
  CheckInterceptorIC(getter, nullptr, query, nullptr,
                     v8::PropertyHandlerFlags::kNone, source, expected);
}

void CheckInterceptorLoadIC(v8::NamedPropertyGetterCallback getter,
                            const char* source, int expected) {
  CheckInterceptorIC(getter, nullptr, nullptr, nullptr,
                     v8::PropertyHandlerFlags::kNone, source, expected);
}

v8::Intercepted InterceptorLoadICGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = CcTest::isolate();
  CHECK_EQ(isolate, info.GetIsolate());
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  CHECK(v8_str("data")->Equals(context, info.Data()).FromJust());
  CHECK(v8_str("x")->Equals(context, name).FromJust());
  info.GetReturnValue().Set(v8::Integer::New(isolate, 42));
  return v8::Intercepted::kYes;
}

}  // namespace

// This test should hit the load IC for the interceptor case.
THREADED_TEST(InterceptorLoadIC) {
  CheckInterceptorLoadIC(InterceptorLoadICGetter,
                         "var result = 0;"
                         "for (var i = 0; i < 1000; i++) {"
                         "  result = o.x;"
                         "}",
                         42);
}


// Below go several tests which verify that JITing for various
// configurations of interceptor and explicit fields works fine
// (those cases are special cased to get better performance).

namespace {

v8::Intercepted InterceptorLoadXICGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  if (v8_str("x")->Equals(isolate->GetCurrentContext(), name).FromJust()) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    info.GetReturnValue().Set(42);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted InterceptorLoadXICGetterWithSideEffects(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  // TODO(ishell): figure out what is the test supposed to do regarding
  // producing side effects but claiming that the interceptor hasn't
  // intercepted the operation. Is it about restarting the lookup iterator?
  ApiTestFuzzer::Fuzz();
  CompileRun("interceptor_getter_side_effect()");
  v8::Isolate* isolate = info.GetIsolate();
  if (v8_str("x")->Equals(isolate->GetCurrentContext(), name).FromJust()) {
    info.GetReturnValue().Set(42);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

}  // namespace

THREADED_TEST(InterceptorLoadICWithFieldOnHolder) {
  CheckInterceptorLoadIC(InterceptorLoadXICGetter,
                         "var result = 0;"
                         "o.y = 239;"
                         "for (var i = 0; i < 1000; i++) {"
                         "  result = o.y;"
                         "}",
                         239);
}


THREADED_TEST(InterceptorLoadICWithSubstitutedProto) {
  CheckInterceptorLoadIC(InterceptorLoadXICGetter,
                         "var result = 0;"
                         "o.__proto__ = { 'y': 239 };"
                         "for (var i = 0; i < 1000; i++) {"
                         "  result = o.y + o.x;"
                         "}",
                         239 + 42);
}


THREADED_TEST(InterceptorLoadICWithPropertyOnProto) {
  CheckInterceptorLoadIC(InterceptorLoadXICGetter,
                         "var result = 0;"
                         "o.__proto__.y = 239;"
                         "for (var i = 0; i < 1000; i++) {"
                         "  result = o.y + o.x;"
                         "}",
                         239 + 42);
}


THREADED_TEST(InterceptorLoadICUndefined) {
  CheckInterceptorLoadIC(InterceptorLoadXICGetter,
                         "var result = 0;"
                         "for (var i = 0; i < 1000; i++) {"
                         "  result = (o.y == undefined) ? 239 : 42;"
                         "}",
                         239);
}


THREADED_TEST(InterceptorLoadICWithOverride) {
  CheckInterceptorLoadIC(InterceptorLoadXICGetter,
                         "fst = new Object();  fst.__proto__ = o;"
                         "snd = new Object();  snd.__proto__ = fst;"
                         "var result1 = 0;"
                         "for (var i = 0; i < 1000;  i++) {"
                         "  result1 = snd.x;"
                         "}"
                         "fst.x = 239;"
                         "var result = 0;"
                         "for (var i = 0; i < 1000; i++) {"
                         "  result = snd.x;"
                         "}"
                         "result + result1",
                         239 + 42);
}


// Test the case when we stored field into
// a stub, but interceptor produced value on its own.
THREADED_TEST(InterceptorLoadICFieldNotNeeded) {
  CheckInterceptorLoadIC(
      InterceptorLoadXICGetter,
      "proto = new Object();"
      "o.__proto__ = proto;"
      "proto.x = 239;"
      "for (var i = 0; i < 1000; i++) {"
      "  o.x;"
      // Now it should be ICed and keep a reference to x defined on proto
      "}"
      "var result = 0;"
      "for (var i = 0; i < 1000; i++) {"
      "  result += o.x;"
      "}"
      "result;",
      42 * 1000);
}


// Test the case when we stored field into
// a stub, but it got invalidated later on.
THREADED_TEST(InterceptorLoadICInvalidatedField) {
  CheckInterceptorLoadIC(
      InterceptorLoadXICGetter,
      "proto1 = new Object();"
      "proto2 = new Object();"
      "o.__proto__ = proto1;"
      "proto1.__proto__ = proto2;"
      "proto2.y = 239;"
      "for (var i = 0; i < 1000; i++) {"
      "  o.y;"
      // Now it should be ICed and keep a reference to y defined on proto2
      "}"
      "proto1.y = 42;"
      "var result = 0;"
      "for (var i = 0; i < 1000; i++) {"
      "  result += o.y;"
      "}"
      "result;",
      42 * 1000);
}

namespace {

int interceptor_load_not_handled_calls = 0;
v8::Intercepted InterceptorLoadNotHandled(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ++interceptor_load_not_handled_calls;
  return v8::Intercepted::kNo;
}
}  // namespace

// Test how post-interceptor lookups are done in the non-cacheable
// case: the interceptor should not be invoked during this lookup.
THREADED_TEST(InterceptorLoadICPostInterceptor) {
  interceptor_load_not_handled_calls = 0;
  CheckInterceptorLoadIC(InterceptorLoadNotHandled,
                         "receiver = new Object();"
                         "receiver.__proto__ = o;"
                         "proto = new Object();"
                         "/* Make proto a slow-case object. */"
                         "for (var i = 0; i < 1000; i++) {"
                         "  proto[\"xxxxxxxx\" + i] = [];"
                         "}"
                         "proto.x = 17;"
                         "o.__proto__ = proto;"
                         "var result = 0;"
                         "for (var i = 0; i < 1000; i++) {"
                         "  result += receiver.x;"
                         "}"
                         "result;",
                         17 * 1000);
  CHECK_EQ(1000, interceptor_load_not_handled_calls);
}


// Test the case when we stored field into
// a stub, but it got invalidated later on due to override on
// global object which is between interceptor and fields' holders.
THREADED_TEST(InterceptorLoadICInvalidatedFieldViaGlobal) {
  CheckInterceptorLoadIC(
      InterceptorLoadXICGetter,
      "o.__proto__ = this;"  // set a global to be a proto of o.
      "this.__proto__.y = 239;"
      "for (var i = 0; i < 10; i++) {"
      "  if (o.y != 239) throw 'oops: ' + o.y;"
      // Now it should be ICed and keep a reference to y defined on
      // field_holder.
      "}"
      "this.y = 42;"  // Assign on a global.
      "var result = 0;"
      "for (var i = 0; i < 10; i++) {"
      "  result += o.y;"
      "}"
      "result;",
      42 * 10);
}

static void SetOnThis(Local<Name> name, Local<Value> value,
                      const v8::PropertyCallbackInfo<void>& info) {
  info.This()
      .As<Object>()
      ->CreateDataProperty(info.GetIsolate()->GetCurrentContext(), name, value)
      .FromJust();
}

THREADED_TEST(InterceptorLoadICWithCallbackOnHolder) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorLoadXICGetter));
  templ->SetNativeDataProperty(v8_str("y"), Return239Callback);
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  // Check the case when receiver and interceptor's holder
  // are the same objects.
  v8::Local<Value> value = CompileRun(
      "var result = 0;"
      "for (var i = 0; i < 7; i++) {"
      "  result = o.y;"
      "}");
  CHECK_EQ(239, value->Int32Value(context.local()).FromJust());

  // Check the case when interceptor's holder is in proto chain
  // of receiver.
  value = CompileRun(
      "r = { __proto__: o };"
      "var result = 0;"
      "for (var i = 0; i < 7; i++) {"
      "  result = r.y;"
      "}");
  CHECK_EQ(239, value->Int32Value(context.local()).FromJust());
}


THREADED_TEST(InterceptorLoadICWithCallbackOnProto) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_o = ObjectTemplate::New(isolate);
  templ_o->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorLoadXICGetter));
  v8::Local<v8::ObjectTemplate> templ_p = ObjectTemplate::New(isolate);
  templ_p->SetNativeDataProperty(v8_str("y"), Return239Callback);

  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ_o->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  context->Global()
      ->Set(context.local(), v8_str("p"),
            templ_p->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  // Check the case when receiver and interceptor's holder
  // are the same objects.
  v8::Local<Value> value = CompileRun(
      "o.__proto__ = p;"
      "var result = 0;"
      "for (var i = 0; i < 7; i++) {"
      "  result = o.x + o.y;"
      "}");
  CHECK_EQ(239 + 42, value->Int32Value(context.local()).FromJust());

  // Check the case when interceptor's holder is in proto chain
  // of receiver.
  value = CompileRun(
      "r = { __proto__: o };"
      "var result = 0;"
      "for (var i = 0; i < 7; i++) {"
      "  result = r.x + r.y;"
      "}");
  CHECK_EQ(239 + 42, value->Int32Value(context.local()).FromJust());
}


THREADED_TEST(InterceptorLoadICForCallbackWithOverride) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorLoadXICGetter));
  templ->SetNativeDataProperty(v8_str("y"), Return239Callback);

  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  v8::Local<Value> value = CompileRun(
      "fst = new Object();  fst.__proto__ = o;"
      "snd = new Object();  snd.__proto__ = fst;"
      "var result1 = 0;"
      "for (var i = 0; i < 7;  i++) {"
      "  result1 = snd.x;"
      "}"
      "fst.x = 239;"
      "var result = 0;"
      "for (var i = 0; i < 7; i++) {"
      "  result = snd.x;"
      "}"
      "result + result1");
  CHECK_EQ(239 + 42, value->Int32Value(context.local()).FromJust());
}


// Test the case when we stored callback into
// a stub, but interceptor produced value on its own.
THREADED_TEST(InterceptorLoadICCallbackNotNeeded) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_o = ObjectTemplate::New(isolate);
  templ_o->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorLoadXICGetter));
  v8::Local<v8::ObjectTemplate> templ_p = ObjectTemplate::New(isolate);
  templ_p->SetNativeDataProperty(v8_str("y"), Return239Callback);

  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ_o->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  context->Global()
      ->Set(context.local(), v8_str("p"),
            templ_p->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  v8::Local<Value> value = CompileRun(
      "o.__proto__ = p;"
      "for (var i = 0; i < 7; i++) {"
      "  o.x;"
      // Now it should be ICed and keep a reference to x defined on p
      "}"
      "var result = 0;"
      "for (var i = 0; i < 7; i++) {"
      "  result += o.x;"
      "}"
      "result");
  CHECK_EQ(42 * 7, value->Int32Value(context.local()).FromJust());
}


// Test the case when we stored callback into
// a stub, but it got invalidated later on.
THREADED_TEST(InterceptorLoadICInvalidatedCallback) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_o = ObjectTemplate::New(isolate);
  templ_o->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorLoadXICGetter));
  v8::Local<v8::ObjectTemplate> templ_p = ObjectTemplate::New(isolate);
  templ_p->SetNativeDataProperty(v8_str("y"), Return239Callback, SetOnThis);

  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ_o->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  context->Global()
      ->Set(context.local(), v8_str("p"),
            templ_p->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  v8::Local<Value> value = CompileRun(
      "inbetween = new Object();"
      "o.__proto__ = inbetween;"
      "inbetween.__proto__ = p;"
      "for (var i = 0; i < 10; i++) {"
      "  o.y;"
      // Now it should be ICed and keep a reference to y defined on p
      "}"
      "inbetween.y = 42;"
      "var result = 0;"
      "for (var i = 0; i < 10; i++) {"
      "  result += o.y;"
      "}"
      "result");
  CHECK_EQ(42 * 10, value->Int32Value(context.local()).FromJust());
}


// Test the case when we stored callback into
// a stub, but it got invalidated later on due to override on
// global object which is between interceptor and callbacks' holders.
THREADED_TEST(InterceptorLoadICInvalidatedCallbackViaGlobal) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_o = ObjectTemplate::New(isolate);
  templ_o->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorLoadXICGetter));
  v8::Local<v8::ObjectTemplate> templ_p = ObjectTemplate::New(isolate);
  templ_p->SetNativeDataProperty(v8_str("y"), Return239Callback, SetOnThis);

  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ_o->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  context->Global()
      ->Set(context.local(), v8_str("p"),
            templ_p->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  v8::Local<Value> value = CompileRun(
      "o.__proto__ = this;"
      "this.__proto__ = p;"
      "for (var i = 0; i < 10; i++) {"
      "  if (o.y != 239) throw 'oops: ' + o.y;"
      // Now it should be ICed and keep a reference to y defined on p
      "}"
      "this.y = 42;"
      "var result = 0;"
      "for (var i = 0; i < 10; i++) {"
      "  result += o.y;"
      "}"
      "result");
  CHECK_EQ(42 * 10, value->Int32Value(context.local()).FromJust());
}

// Test load of a non-existing global when a global object has an interceptor.
THREADED_TEST(InterceptorLoadGlobalICGlobalWithInterceptor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_global = v8::ObjectTemplate::New(isolate);
  templ_global->SetHandler(v8::NamedPropertyHandlerConfiguration(
      EmptyInterceptorGetter, EmptyInterceptorSetter));

  LocalContext context(nullptr, templ_global);
  i::DirectHandle<i::JSReceiver> global_proxy =
      v8::Utils::OpenDirectHandle<Object, i::JSReceiver>(context->Global());
  CHECK(IsJSGlobalProxy(*global_proxy));
  i::DirectHandle<i::JSGlobalObject> global(
      i::Cast<i::JSGlobalObject>(global_proxy->map()->prototype()),
      global_proxy->GetIsolate());
  CHECK(global->map()->has_named_interceptor());

  v8::Local<Value> value = CompileRun(
      "var f = function() { "
      "  try {"
      "    x1;"
      "  } catch(e) {"
      "  }"
      "  return typeof x1 === 'undefined';"
      "};"
      "for (var i = 0; i < 10; i++) {"
      "  f();"
      "};"
      "f();");
  CHECK(value->BooleanValue(isolate));

  value = CompileRun(
      "var f = function() { "
      "  try {"
      "    x2;"
      "    return false;"
      "  } catch(e) {"
      "    return true;"
      "  }"
      "};"
      "for (var i = 0; i < 10; i++) {"
      "  f();"
      "};"
      "f();");
  CHECK(value->BooleanValue(isolate));

  value = CompileRun(
      "var f = function() { "
      "  try {"
      "    typeof(x3);"
      "    return true;"
      "  } catch(e) {"
      "    return false;"
      "  }"
      "};"
      "for (var i = 0; i < 10; i++) {"
      "  f();"
      "};"
      "f();");
  CHECK(value->BooleanValue(isolate));
}

// Test load of a non-existing global through prototype chain when a global
// object has an interceptor.
THREADED_TEST(InterceptorLoadICGlobalWithInterceptor) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_global = v8::ObjectTemplate::New(isolate);
  templ_global->SetHandler(v8::NamedPropertyHandlerConfiguration(
      GenericInterceptorGetter, GenericInterceptorSetter));

  LocalContext context(nullptr, templ_global);
  i::DirectHandle<i::JSReceiver> global_proxy =
      v8::Utils::OpenDirectHandle<Object, i::JSReceiver>(context->Global());
  CHECK(IsJSGlobalProxy(*global_proxy));
  i::DirectHandle<i::JSGlobalObject> global(
      i::Cast<i::JSGlobalObject>(global_proxy->map()->prototype()),
      global_proxy->GetIsolate());
  CHECK(global->map()->has_named_interceptor());

  ExpectInt32(
      "(function() {"
      "  var f = function(obj) { "
      "    return obj.foo;"
      "  };"
      "  var obj = { __proto__: this, _str_foo: 42 };"
      "  for (var i = 0; i < 1500; i++) obj['p' + i] = 0;"
      "  /* Ensure that |obj| is in dictionary mode. */"
      "  if (%HasFastProperties(obj)) return -1;"
      "  for (var i = 0; i < 3; i++) {"
      "    f(obj);"
      "  };"
      "  return f(obj);"
      "})();",
      42);
}

namespace {
v8::Intercepted InterceptorLoadICGetter0(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  CHECK(v8_str("x")
            ->Equals(info.GetIsolate()->GetCurrentContext(), name)
            .FromJust());
  info.GetReturnValue().Set(0);
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(InterceptorReturningZero) {
  CheckInterceptorLoadIC(InterceptorLoadICGetter0, "o.x == undefined ? 1 : 0",
                         0);
}

namespace {

template <typename TKey, v8::internal::PropertyAttributes attribute>
v8::Intercepted HasICQuery(TKey name,
                           const v8::PropertyCallbackInfo<v8::Integer>& info) {
  v8::Isolate* isolate = CcTest::isolate();
  CHECK_EQ(isolate, info.GetIsolate());
  if (attribute != v8::internal::ABSENT) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    info.GetReturnValue().Set(attribute);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

template <typename TKey>
v8::Intercepted HasICQueryToggle(
    TKey name, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  static bool is_absent = false;
  is_absent = !is_absent;
  v8::Isolate* isolate = CcTest::isolate();
  CHECK_EQ(isolate, info.GetIsolate());
  if (!is_absent) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    info.GetReturnValue().Set(v8::None);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

template <typename TKey, v8::internal::PropertyAttributes attribute>
v8::Intercepted HasICQuerySideEffect(
    TKey name, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  if (attribute != v8::internal::ABSENT) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
  }
  v8::Isolate* isolate = CcTest::isolate();
  CHECK_EQ(isolate, info.GetIsolate());
  CompileRun("interceptor_query_side_effect()");
  if (attribute != v8::internal::ABSENT) {
    info.GetReturnValue().Set(attribute);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

int named_query_counter = 0;
v8::Intercepted NamedQueryCallback(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  named_query_counter++;
  return v8::Intercepted::kNo;
}

}  // namespace

THREADED_TEST(InterceptorHasIC) {
  named_query_counter = 0;
  CheckInterceptorIC(nullptr, NamedQueryCallback,
                     "var result = 0;"
                     "for (var i = 0; i < 1000; i++) {"
                     "  'x' in o;"
                     "}",
                     0);
  CHECK_EQ(1000, named_query_counter);
}

THREADED_TEST(InterceptorHasICQueryAbsent) {
  CheckInterceptorIC(nullptr, HasICQuery<Local<Name>, v8::internal::ABSENT>,
                     "var result = 0;"
                     "for (var i = 0; i < 1000; i++) {"
                     "  if ('x' in o) ++result;"
                     "}",
                     0);
}

THREADED_TEST(InterceptorHasICQueryNone) {
  CheckInterceptorIC(nullptr, HasICQuery<Local<Name>, v8::internal::NONE>,
                     "var result = 0;"
                     "for (var i = 0; i < 1000; i++) {"
                     "  if ('x' in o) ++result;"
                     "}",
                     1000);
}

THREADED_TEST(InterceptorHasICGetter) {
  CheckInterceptorIC(InterceptorLoadICGetter, nullptr,
                     "var result = 0;"
                     "for (var i = 0; i < 1000; i++) {"
                     "  if ('x' in o) ++result;"
                     "}",
                     1000);
}

THREADED_TEST(InterceptorHasICQueryGetter) {
  CheckInterceptorIC(InterceptorLoadICGetter,
                     HasICQuery<Local<Name>, v8::internal::ABSENT>,
                     "var result = 0;"
                     "for (var i = 0; i < 1000; i++) {"
                     "  if ('x' in o) ++result;"
                     "}",
                     0);
}

THREADED_TEST(InterceptorHasICQueryToggle) {
  CheckInterceptorIC(InterceptorLoadICGetter, HasICQueryToggle<Local<Name>>,
                     "var result = 0;"
                     "for (var i = 0; i < 1000; i++) {"
                     "  if ('x' in o) ++result;"
                     "}",
                     500);
}

THREADED_TEST(InterceptorStoreICWithSideEffectfulCallbacks1) {
  CheckInterceptorIC(EmptyInterceptorGetter,
                     HasICQuerySideEffect<Local<Name>, v8::internal::NONE>,
                     "let r;"
                     "let inside_side_effect = false;"
                     "let interceptor_query_side_effect = function() {"
                     "  if (!inside_side_effect) {"
                     "    inside_side_effect = true;"
                     "    r.x = 153;"
                     "    inside_side_effect = false;"
                     "  }"
                     "};"
                     "for (var i = 0; i < 20; i++) {"
                     "  r = { __proto__: o };"
                     "  r.x = i;"
                     "}",
                     19);
}

TEST(Crash_InterceptorStoreICWithSideEffectfulCallbacks1) {
  CheckInterceptorIC(EmptyInterceptorGetter,
                     HasICQuerySideEffect<Local<Name>, v8::internal::ABSENT>,
                     "let r;"
                     "let inside_side_effect = false;"
                     "let interceptor_query_side_effect = function() {"
                     "  if (!inside_side_effect) {"
                     "    inside_side_effect = true;"
                     "    r.x = 153;"
                     "    inside_side_effect = false;"
                     "  }"
                     "};"
                     "for (var i = 0; i < 20; i++) {"
                     "  r = { __proto__: o };"
                     "  r.x = i;"
                     "}",
                     19);
}

TEST(Crash_InterceptorStoreICWithSideEffectfulCallbacks2) {
  CheckInterceptorIC(InterceptorLoadXICGetterWithSideEffects,
                     nullptr,  // query callback is not provided
                     "let r;"
                     "let inside_side_effect = false;"
                     "let interceptor_getter_side_effect = function() {"
                     "  if (!inside_side_effect) {"
                     "    inside_side_effect = true;"
                     "    r.y = 153;"
                     "    inside_side_effect = false;"
                     "  }"
                     "};"
                     "for (var i = 0; i < 20; i++) {"
                     "  r = { __proto__: o };"
                     "  r.y = i;"
                     "}",
                     19);
}

THREADED_TEST(InterceptorDefineICWithSideEffectfulCallbacks) {
  CheckInterceptorIC(EmptyInterceptorGetter, EmptyInterceptorSetter,
                     EmptyInterceptorQuery,
                     EmptyInterceptorDefinerWithSideEffect,
                     v8::PropertyHandlerFlags::kNonMasking,
                     "let inside_side_effect = false;"
                     "let interceptor_definer_side_effect = function() {"
                     "  if (!inside_side_effect) {"
                     "    inside_side_effect = true;"
                     "    o.y = 153;"
                     "    inside_side_effect = false;"
                     "  }"
                     "  return true;"  // Accept the request.
                     "};"
                     "class Base {"
                     "  constructor(arg) {"
                     "    return arg;"
                     "  }"
                     "}"
                     "class ClassWithField extends Base {"
                     "  y = (() => {"
                     "    return 42;"
                     "  })();"
                     "  constructor(arg) {"
                     "    super(arg);"
                     "  }"
                     "}"
                     "new ClassWithField(o);"
                     "o.y",
                     153);
}

TEST(Crash_InterceptorDefineICWithSideEffectfulCallbacks) {
  CheckInterceptorIC(EmptyInterceptorGetter, EmptyInterceptorSetter,
                     EmptyInterceptorQuery,
                     EmptyInterceptorDefinerWithSideEffect,
                     v8::PropertyHandlerFlags::kNonMasking,
                     "let inside_side_effect = false;"
                     "let interceptor_definer_side_effect = function() {"
                     "  if (!inside_side_effect) {"
                     "    inside_side_effect = true;"
                     "    o.y = 153;"
                     "    inside_side_effect = false;"
                     "  }"
                     "  return null;"  // Decline the request.
                     "};"
                     "class Base {"
                     "  constructor(arg) {"
                     "    return arg;"
                     "  }"
                     "}"
                     "class ClassWithField extends Base {"
                     "  y = (() => {"
                     "    return 42;"
                     "  })();"
                     "  constructor(arg) {"
                     "    super(arg);"
                     "  }"
                     "}"
                     "new ClassWithField(o);"
                     "o.y",
                     42);
}

namespace {
v8::Intercepted InterceptorStoreICSetter(
    Local<Name> key, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  CHECK(v8_str("x")->Equals(context, key).FromJust());
  CHECK_EQ(42, value->Int32Value(context).FromJust());
  return v8::Intercepted::kYes;
}
}  // namespace

// This test should hit the store IC for the interceptor case.
THREADED_TEST(InterceptorStoreIC) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
      InterceptorLoadICGetter, InterceptorStoreICSetter, nullptr, nullptr,
      nullptr, v8_str("data")));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "for (var i = 0; i < 1000; i++) {"
      "  o.x = 42;"
      "}");
}


THREADED_TEST(InterceptorStoreICWithNoSetter) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorLoadXICGetter));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<Value> value = CompileRun(
      "for (var i = 0; i < 1000; i++) {"
      "  o.y = 239;"
      "}"
      "42 + o.y");
  CHECK_EQ(239 + 42, value->Int32Value(context.local()).FromJust());
}

THREADED_TEST(EmptyInterceptorDoesNotShadowReadOnlyProperty) {
  // Interceptor should not shadow readonly property 'x' on the prototype, and
  // attempt to store to 'x' must throw.
  CheckInterceptorIC(EmptyInterceptorGetter,
                     HasICQuery<Local<Name>, v8::internal::ABSENT>,
                     "'use strict';"
                  
"""


```