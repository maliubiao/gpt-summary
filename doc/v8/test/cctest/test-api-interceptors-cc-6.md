Response:
The user wants a summary of the provided C++ code snippet. This code is a V8 test file focusing on `test-api-interceptors.cc`.

Here's a breakdown of how to address the request:

1. **Identify the core functionality:** The file name suggests it's testing API interceptors in V8. The code confirms this by setting up object templates with various interceptor configurations.

2. **List the functionalities demonstrated:** Go through the code blocks and identify the different scenarios being tested. This includes:
    * Interceptors throwing exceptions during enumeration.
    * Preprocessing of exceptions thrown by interceptors.
    * Non-masking interceptors.
    * Custom enumeration behavior.
    * Restricting enumeration based on query interceptors.

3. **Check for Torque:** The filename ends with `.cc`, not `.tq`, so it's not a Torque file.

4. **Relate to JavaScript:**  Interceptors in V8 directly relate to how JavaScript interacts with objects, especially when accessing or manipulating properties. Provide JavaScript examples that would trigger these interceptors.

5. **Identify code logic and examples:**  The code tests how exceptions are handled during property access and enumeration. Provide scenarios with expected inputs and outputs based on whether interceptors throw exceptions.

6. **Highlight common programming errors:**  Focus on errors related to unexpected behavior due to interceptors, especially when they throw exceptions or modify enumeration.

7. **Summarize the overall functionality:** Combine the identified functionalities into a concise summary, considering this is part 7 of 8. This part seems to focus on exception handling and advanced interceptor configurations like non-masking and custom enumeration.
这是 `v8/test/cctest/test-api-interceptors.cc` 源代码的第七部分，它主要关注 **V8 API 拦截器** 的功能测试，特别是关于 **异常处理** 和 **属性枚举** 方面的测试。

**功能列举:**

1. **测试枚举器拦截器抛出异常时的行为 (IndexedPropertyEnumeratorException & NamedPropertyEnumeratorException):**  验证当 `for...in` 循环和 `Object.keys()` 遇到抛出异常的枚举器拦截器时，V8 的处理方式。

2. **测试异常预处理回调 (PreprocessExceptionTestCallback):**  演示如何使用 `SetExceptionPropagationCallback` 来设置一个全局的异常预处理回调函数，该回调可以在异常抛出后，但在被 JavaScript 代码捕获之前对其进行修改或记录。  它测试了在各种拦截器回调（query, getter, setter, deleter, definer, descriptor）中抛出异常时，预处理回调如何被触发，并能访问到相关的异常信息和上下文。

3. **测试非屏蔽拦截器 (NonMasking Interceptor):**  验证 `kNonMasking` 属性处理器标志的行为。非屏蔽拦截器即使在对象自身或其原型链上存在同名属性时也会被触发。

4. **测试自定义属性枚举 (EnumCallbackWithNames & EnumCallbackWithIndices):**  展示如何通过设置枚举器拦截器来完全自定义一个对象的属性枚举行为，包括返回哪些属性以及它们的顺序。

5. **测试通过查询拦截器限制属性枚举 (RestrictiveNamedQuery & RestrictiveIndexedQuery):**  演示如何使用查询拦截器 (`NamedPropertyQueryCallback` 和 `IndexedPropertyQueryCallback`) 来控制哪些属性可以被枚举，即使枚举器拦截器返回了这些属性。

**关于文件类型:**

`v8/test/cctest/test-api-interceptors.cc` 以 `.cc` 结尾，所以它是 **V8 的 C++ 源代码**，而不是 Torque 源代码。

**与 JavaScript 的功能关系及举例:**

V8 的 API 拦截器允许 C++ 代码介入 JavaScript 对象的属性访问、设置、删除、枚举等操作。以下 JavaScript 例子可以触发本代码中测试的拦截器行为：

```javascript
const obj = {};
// 假设 'obj' 对象在 C++ 代码中设置了相应的拦截器

// 触发枚举器拦截器
for (let key in obj) {
  console.log(key);
}
console.log(Object.keys(obj));

// 触发 getter 拦截器
console.log(obj.someProperty);
console.log(obj[0]);

// 触发 setter 拦截器
obj.anotherProperty = 123;
obj[1] = 'hello';

// 触发 deleter 拦截器
delete obj.yetAnotherProperty;
delete obj[2];

// 触发 definer 拦截器
Object.defineProperty(obj, 'newProperty', { value: 456 });

// 触发 descriptor 拦截器
Object.getOwnPropertyDescriptor(obj, 'existingProperty');
```

**代码逻辑推理与假设输入输出:**

**场景 1: 测试枚举器拦截器抛出异常**

**假设输入 (C++):**
* 创建一个对象模板 `obj_template`。
* 为 `obj_template` 设置一个索引属性枚举器拦截器 `IndexedPropertyEnumeratorException`，该拦截器会抛出一个值为 42 的异常。
* 创建一个基于 `obj_template` 的对象 `object`。

**JavaScript 代码:**
```javascript
var result  = [];
try {
  for (var k in object) result .push(k);
} catch (e) {
  result  = e;
}
result;
```

**预期输出 (JavaScript):**  由于枚举器抛出了异常，`for...in` 循环会被 `catch` 捕获，`result` 的值将是异常值 `42`。

**场景 2: 测试异常预处理回调**

**假设输入 (C++):**
* 设置了 `PreprocessExceptionTestCallback` 作为全局异常预处理回调。
* 创建一个对象 `obj`，其属性访问操作会触发抛出异常的拦截器 (例如 `PETNamedGetter` 在 `config.getter_should_throw` 为 `true` 时会抛出异常)。

**JavaScript 代码:**
```javascript
try {
  obj.foo; // 触发 NamedGetter 拦截器，假设会抛出异常
} catch (e) {
  console.log(e.message);
}
```

**预期输出 (JavaScript 的控制台输出):**  异常预处理回调会修改异常对象，添加包含接口名、属性名和异常上下文信息的 `message` 属性。 预期输出类似于 `"MyClass:foo:NamedGetter: Named getter failed."`。

**用户常见的编程错误:**

1. **没有考虑到拦截器可能抛出异常:** 用户编写的 JavaScript 代码可能没有考虑到对象上的拦截器可能会抛出异常，导致程序崩溃或出现未预期的行为。例如，在迭代一个设置了抛出异常的枚举器拦截器的对象时，如果没有使用 `try...catch` 包裹，就会导致错误。

   ```javascript
   const myObjWithInterceptor = {}; // 假设这个对象有抛出异常的枚举器拦截器
   // 错误的做法，没有考虑异常
   for (const key in myObjWithInterceptor) {
       console.log(key);
   }

   // 正确的做法，使用 try...catch
   try {
       for (const key in myObjWithInterceptor) {
           console.log(key);
       }
   } catch (error) {
       console.error("枚举对象时发生错误:", error);
   }
   ```

2. **依赖于默认的属性枚举行为，但对象设置了自定义枚举器:**  用户可能期望 `for...in` 或 `Object.keys()` 返回对象的所有属性，但如果对象设置了自定义的枚举器拦截器，返回的属性可能与预期不符。

   ```javascript
   const myObjWithCustomEnumerator = {}; // 假设这个对象有自定义枚举器
   myObjWithCustomEnumerator.a = 1;
   myObjWithCustomEnumerator.b = 2;
   myObjWithCustomEnumerator.c = 3;

   // 用户可能期望输出 a, b, c
   for (const key in myObjWithCustomEnumerator) {
       console.log(key); // 实际输出可能只包含自定义枚举器返回的属性
   }
   ```

**第 7 部分功能归纳:**

这部分代码主要测试了 V8 API 拦截器在 **异常处理** 和 **属性枚举** 方面的行为。具体来说，它验证了当拦截器（特别是枚举器）抛出异常时 V8 的处理方式，以及如何通过设置异常预处理回调来干预异常处理流程。此外，还深入测试了非屏蔽拦截器的特性，以及如何通过枚举器和查询拦截器来定制对象的属性枚举行为。这部分强调了 V8 拦截器机制的强大功能和灵活性，以及在处理由拦截器引发的异常时需要注意的事项。

### 提示词
```
这是目录为v8/test/cctest/test-api-interceptors.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api-interceptors.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
Set(isolate, "x", v8::Integer::New(isolate, 42));
  // First just try a failing indexed interceptor.
  obj_template->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      static_cast<v8::IndexedPropertyGetterCallbackV2>(nullptr), nullptr,
      nullptr, nullptr, IndexedPropertyEnumeratorException));

  LocalContext context;
  v8::Local<v8::Object> global = context->Global();
  global->Set(context.local(), v8_str("object"),
              obj_template->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<v8::Value> result = CompileRun(
      "var result  = []; "
      "try { "
      "  for (var k in object) result .push(k);"
      "} catch (e) {"
      "  result  = e"
      "}"
      "result ");
  CHECK(!result->IsArray());
  CHECK(v8_num(42)->Equals(context.local(), result).FromJust());

  result = CompileRun(
      "var result = [];"
      "try { "
      "  result = Object.keys(object);"
      "} catch (e) {"
      "  result = e;"
      "}"
      "result");
  CHECK(!result->IsArray());
  CHECK(v8_num(42)->Equals(context.local(), result).FromJust());
}

namespace {
void NamedPropertyEnumeratorException(
    const v8::PropertyCallbackInfo<v8::Array>& info) {
  info.GetIsolate()->ThrowException(v8_num(43));
}
}  // namespace

THREADED_TEST(GetOwnPropertyNamesWithNamedInterceptorExceptions_regress4026) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> obj_template = v8::ObjectTemplate::New(isolate);

  obj_template->Set(isolate, "7", v8::Integer::New(isolate, 7));
  obj_template->Set(isolate, "x", v8::Integer::New(isolate, 42));
  // First just try a failing indexed interceptor.
  obj_template->SetHandler(v8::NamedPropertyHandlerConfiguration(
      static_cast<v8::NamedPropertyGetterCallback>(nullptr), nullptr, nullptr,
      nullptr, NamedPropertyEnumeratorException));

  LocalContext context;
  v8::Local<v8::Object> global = context->Global();
  global->Set(context.local(), v8_str("object"),
              obj_template->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  v8::Local<v8::Value> result = CompileRun(
      "var result = []; "
      "try { "
      "  for (var k in object) result.push(k);"
      "} catch (e) {"
      "  result = e"
      "}"
      "result");
  CHECK(!result->IsArray());
  CHECK(v8_num(43)->Equals(context.local(), result).FromJust());

  result = CompileRun(
      "var result = [];"
      "try { "
      "  result = Object.keys(object);"
      "} catch (e) {"
      "  result = e;"
      "}"
      "result");
  CHECK(!result->IsArray());
  CHECK(v8_num(43)->Equals(context.local(), result).FromJust());
}

namespace {

struct PreprocessExceptionTestConfig {
  bool query_should_throw : 1 = false;
  bool getter_should_throw : 1 = false;
  bool descriptor_should_throw : 1 = false;
};

template <typename T>
PreprocessExceptionTestConfig* GetPETConfig(
    const v8::PropertyCallbackInfo<T>& info) {
  return reinterpret_cast<PreprocessExceptionTestConfig*>(
      v8::External::Cast(*info.Data())->Value());
}

const char* ToString(v8::ExceptionContext kind) {
  switch (kind) {
    case v8::ExceptionContext::kUnknown:
      return "Unknown";
    case v8::ExceptionContext::kConstructor:
      return "Constructor";
    case v8::ExceptionContext::kOperation:
      return "Operation";
    case v8::ExceptionContext::kAttributeGet:
      return "AttributeGet";
    case v8::ExceptionContext::kAttributeSet:
      return "AttributeSet";
    case v8::ExceptionContext::kIndexedQuery:
      return "IndexedQuery";
    case v8::ExceptionContext::kIndexedGetter:
      return "IndexedGetter";
    case v8::ExceptionContext::kIndexedDescriptor:
      return "IndexedDescriptor";
    case v8::ExceptionContext::kIndexedSetter:
      return "IndexedSetter";
    case v8::ExceptionContext::kIndexedDefiner:
      return "IndexedDefiner";
    case v8::ExceptionContext::kIndexedDeleter:
      return "IndexedDeleter";
    case v8::ExceptionContext::kNamedQuery:
      return "NamedQuery";
    case v8::ExceptionContext::kNamedGetter:
      return "NamedGetter";
    case v8::ExceptionContext::kNamedDescriptor:
      return "NamedDescriptor";
    case v8::ExceptionContext::kNamedSetter:
      return "NamedSetter";
    case v8::ExceptionContext::kNamedDefiner:
      return "NamedDefiner";
    case v8::ExceptionContext::kNamedDeleter:
      return "NamedDeleter";
    case v8::ExceptionContext::kNamedEnumerator:
      return "NamedEnumerator";
  }
  UNREACHABLE();
}

void PreprocessExceptionTestCallback(v8::ExceptionPropagationMessage info) {
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Object> exception = info.GetException();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::String> message_key = v8_str("message");

  v8::Local<v8::String> message_value = exception->Get(context, message_key)
                                            .ToLocalChecked()
                                            ->ToString(context)
                                            .ToLocalChecked();
  String::Utf8Value interface_name(isolate, info.GetInterfaceName());
  String::Utf8Value property_name(isolate, info.GetPropertyName());
  String::Utf8Value message(isolate, message_value);

  v8::base::ScopedVector<char> buf(256);
  v8::base::SNPrintF(buf, "%s:%s:%s: %s", *interface_name, *property_name,
                     ToString(info.GetExceptionContext()), *message);

  std::ignore =
      exception->CreateDataProperty(context, message_key, v8_str(buf.data()));
}

void CheckMessage(v8::TryCatch& try_catch, const char* expected_message) {
  CHECK(try_catch.HasCaught());
  v8::Local<v8::String> message_key = v8_str("message");
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();

  Local<v8::Value> result = try_catch.Exception()
                                .As<v8::Object>()
                                ->Get(context, message_key)
                                .ToLocalChecked();
  CHECK(result->IsString());
  String::Utf8Value message(isolate, result.As<String>());

  // Compare as std::string in order to see a readable message on failure.
  CHECK_EQ(std::string(*message), std::string(expected_message));
  try_catch.Reset();
}

// Named interceptor callbacks.

v8::Intercepted PETNamedQuery(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  if (GetPETConfig(info)->query_should_throw) {
    info.GetIsolate()->ThrowError(v8_str("Named query failed."));
  } else {
    info.GetReturnValue().Set(v8::None);
  }
  return v8::Intercepted::kYes;
}
v8::Intercepted PETNamedGetter(Local<Name> name,
                               const v8::PropertyCallbackInfo<Value>& info) {
  if (GetPETConfig(info)->getter_should_throw) {
    info.GetIsolate()->ThrowError(v8_str("Named getter failed."));
  } else {
    info.GetReturnValue().Set(153);
  }
  return v8::Intercepted::kYes;
}
v8::Intercepted PETNamedSetter(Local<Name> name, Local<Value> value,
                               const v8::PropertyCallbackInfo<void>& info) {
  info.GetIsolate()->ThrowError(v8_str("Named setter failed."));
  return v8::Intercepted::kYes;
}
v8::Intercepted PETNamedDeleter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  info.GetIsolate()->ThrowError(v8_str("Named deleter failed."));
  return v8::Intercepted::kYes;
}
v8::Intercepted PETNamedDefiner(Local<Name> name,
                                const v8::PropertyDescriptor& desc,
                                const v8::PropertyCallbackInfo<void>& info) {
  info.GetIsolate()->ThrowError(v8_str("Named definer failed."));
  return v8::Intercepted::kYes;
}
v8::Intercepted PETNamedDescriptor(
    Local<Name> property, const v8::PropertyCallbackInfo<Value>& info) {
  if (GetPETConfig(info)->descriptor_should_throw) {
    info.GetIsolate()->ThrowError(v8_str("Named descriptor failed."));
  } else {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Object> descriptor = v8::Object::New(isolate);
    v8::Local<v8::Context> ctx = isolate->GetCurrentContext();
    v8::Local<v8::Boolean> true_value = v8::Boolean::New(isolate, true);

    std::ignore = descriptor->Set(ctx, v8_str("value"), property);
    std::ignore = descriptor->Set(ctx, v8_str("writable"), true_value);
    std::ignore = descriptor->Set(ctx, v8_str("enumerable"), true_value);
    std::ignore = descriptor->Set(ctx, v8_str("configurable"), true_value);

    info.GetReturnValue().Set(descriptor);
  }
  return v8::Intercepted::kYes;
}

// Indexed interceptor callbacks.

v8::Intercepted PETIndexedQuery(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  if (GetPETConfig(info)->query_should_throw) {
    info.GetIsolate()->ThrowError(v8_str("Indexed query failed."));
  } else {
    info.GetReturnValue().Set(v8::None);
  }
  return v8::Intercepted::kYes;
}
v8::Intercepted PETIndexedGetter(uint32_t index,
                                 const v8::PropertyCallbackInfo<Value>& info) {
  if (GetPETConfig(info)->getter_should_throw) {
    info.GetIsolate()->ThrowError(v8_str("Indexed getter failed."));
  } else {
    info.GetReturnValue().Set(153);
  }
  return v8::Intercepted::kYes;
}
v8::Intercepted PETIndexedSetter(uint32_t index, Local<Value> value,
                                 const v8::PropertyCallbackInfo<void>& info) {
  info.GetIsolate()->ThrowError(v8_str("Indexed setter failed."));
  return v8::Intercepted::kYes;
}
v8::Intercepted PETIndexedDeleter(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  info.GetIsolate()->ThrowError(v8_str("Indexed deleter failed."));
  return v8::Intercepted::kYes;
}
v8::Intercepted PETIndexedDefiner(uint32_t index,
                                  const v8::PropertyDescriptor& desc,
                                  const v8::PropertyCallbackInfo<void>& info) {
  info.GetIsolate()->ThrowError(v8_str("Indexed definer failed."));
  return v8::Intercepted::kYes;
}
v8::Intercepted PETIndexedDescriptor(
    uint32_t index, const v8::PropertyCallbackInfo<Value>& info) {
  if (GetPETConfig(info)->descriptor_should_throw) {
    info.GetIsolate()->ThrowError(v8_str("Indexed descriptor failed."));
  } else {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Object> descriptor = v8::Object::New(isolate);
    v8::Local<v8::Context> ctx = isolate->GetCurrentContext();
    v8::Local<v8::Boolean> true_value = v8::Boolean::New(isolate, true);

    std::ignore = descriptor->Set(ctx, v8_str("value"), v8_uint(index));
    std::ignore = descriptor->Set(ctx, v8_str("writable"), true_value);
    std::ignore = descriptor->Set(ctx, v8_str("enumerable"), true_value);
    std::ignore = descriptor->Set(ctx, v8_str("configurable"), true_value);

    info.GetReturnValue().Set(descriptor);
  }
  return v8::Intercepted::kYes;
}

}  // namespace

void TestPreprocessExceptionFromInterceptors(
    v8::Isolate* isolate, PreprocessExceptionTestConfig& config,
    Local<Context> ctx, v8::Local<v8::Object> obj,
    bool is_descriptor_callback_available) {
  v8::TryCatch try_catch(isolate);

  config.query_should_throw = true;
  config.getter_should_throw = true;
  config.descriptor_should_throw = true;

  const char* expected;
  //
  // Check query callbacks.
  //
  {
    expected = "MyClass:foo:NamedQuery: Named query failed.";
    std::ignore = obj->GetPropertyAttributes(ctx, v8_str("foo"));
    CheckMessage(try_catch, expected);
    std::ignore = obj->HasOwnProperty(ctx, v8_str("foo"));
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("Object.hasOwn(obj, 'foo');");
    CheckMessage(try_catch, expected);

    expected = "MyClass:1:IndexedQuery: Indexed query failed.";
    std::ignore = obj->GetPropertyAttributes(ctx, v8_uint(1));
    CheckMessage(try_catch, expected);
    std::ignore = obj->HasOwnProperty(ctx, v8_str("1"));
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("Object.hasOwn(obj, 1);");
    CheckMessage(try_catch, expected);

    expected = "MyClass:4294967294:IndexedQuery: Indexed query failed.";
    std::ignore = obj->GetPropertyAttributes(ctx, v8_uint(0xfffffffe));
    CheckMessage(try_catch, expected);
    std::ignore = obj->HasOwnProperty(ctx, v8_str("4294967294"));
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("Object.hasOwn(obj, 0xfffffffe);");
    CheckMessage(try_catch, expected);

    expected = "MyClass:4294967295:NamedQuery: Named query failed.";
    std::ignore = obj->GetPropertyAttributes(ctx, v8_uint(0xffffffff));
    CheckMessage(try_catch, expected);
    std::ignore = obj->HasOwnProperty(ctx, v8_str("4294967295"));
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("Object.hasOwn(obj, 0xffffffff);");
    CheckMessage(try_catch, expected);
  }

  //
  // Check getter callbacks.
  //
  {
    expected = "MyClass:foo:NamedGetter: Named getter failed.";
    std::ignore = obj->Get(ctx, v8_str("foo"));
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("obj.foo");
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("obj['foo']");
    CheckMessage(try_catch, expected);

    expected = "MyClass:1:IndexedGetter: Indexed getter failed.";
    std::ignore = obj->Get(ctx, v8_uint(1));
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("obj[1]");
    CheckMessage(try_catch, expected);

    expected = "MyClass:4294967294:IndexedGetter: Indexed getter failed.";
    std::ignore = obj->Get(ctx, v8_uint(0xfffffffe));
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("obj[0xfffffffe]");
    CheckMessage(try_catch, expected);

    expected = "MyClass:4294967295:NamedGetter: Named getter failed.";
    std::ignore = obj->Get(ctx, v8_uint(0xffffffff));
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("obj[0xffffffff]");
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("obj[4294967295]");
    CheckMessage(try_catch, expected);
  }

  //
  // Check setter callbacks.
  //
  {
    v8::Local<v8::Value> value = v8_str("value");

    expected = "MyClass:foo:NamedSetter: Named setter failed.";
    std::ignore = obj->Set(ctx, v8_str("foo"), value);
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("obj.foo = 42;");
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("obj['foo'] = 42;");
    CheckMessage(try_catch, expected);

    expected = "MyClass:1:IndexedSetter: Indexed setter failed.";
    std::ignore = obj->Set(ctx, v8_uint(1), value);
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("obj[1] = 42;");
    CheckMessage(try_catch, expected);

    expected = "MyClass:4294967294:IndexedSetter: Indexed setter failed.";
    std::ignore = obj->Set(ctx, v8_uint(0xfffffffe), value);
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("obj[0xfffffffe] = 42;");
    CheckMessage(try_catch, expected);

    expected = "MyClass:4294967295:NamedSetter: Named setter failed.";
    std::ignore = obj->Set(ctx, v8_uint(0xffffffff), value);
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("obj[0xffffffff] = 42;");
    CheckMessage(try_catch, expected);
  }

  //
  // Check deleter callbacks.
  //
  {
    expected = "MyClass:foo:NamedDeleter: Named deleter failed.";
    std::ignore = obj->Delete(ctx, v8_str("foo"));
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("delete obj.foo;");
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("delete obj['foo'];");
    CheckMessage(try_catch, expected);

    expected = "MyClass:1:IndexedDeleter: Indexed deleter failed.";
    std::ignore = obj->Delete(ctx, v8_str("1"));
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("delete obj[1];");
    CheckMessage(try_catch, expected);

    expected = "MyClass:4294967294:IndexedDeleter: Indexed deleter failed.";
    std::ignore = obj->Delete(ctx, v8_str("4294967294"));
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("delete obj[0xfffffffe];");
    CheckMessage(try_catch, expected);

    expected = "MyClass:4294967295:NamedDeleter: Named deleter failed.";
    std::ignore = obj->Delete(ctx, v8_str("4294967295"));
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("delete obj[0xffffffff];");
    CheckMessage(try_catch, expected);
  }

  //
  // Check descriptor callbacks.
  //
  {
    expected = is_descriptor_callback_available
                   ? "MyClass:foo:NamedDescriptor: Named descriptor failed."
                   : "MyClass:foo:NamedQuery: Named query failed.";
    std::ignore = obj->GetOwnPropertyDescriptor(ctx, v8_str("foo"));
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("Object.getOwnPropertyDescriptor(obj, 'foo');");
    CheckMessage(try_catch, expected);

    expected = is_descriptor_callback_available
                   ? "MyClass:1:IndexedDescriptor: Indexed descriptor failed."
                   : "MyClass:1:IndexedQuery: Indexed query failed.";
    std::ignore = obj->GetOwnPropertyDescriptor(ctx, v8_str("1"));
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("Object.getOwnPropertyDescriptor(obj, 1);");
    CheckMessage(try_catch, expected);

    expected =
        is_descriptor_callback_available
            ? "MyClass:4294967294:IndexedDescriptor: Indexed descriptor failed."
            : "MyClass:4294967294:IndexedQuery: Indexed query failed.";
    std::ignore = obj->GetOwnPropertyDescriptor(ctx, v8_str("4294967294"));
    CheckMessage(try_catch, expected);
    std::ignore =
        CompileRun("Object.getOwnPropertyDescriptor(obj, 0xfffffffe);");
    CheckMessage(try_catch, expected);

    expected =
        is_descriptor_callback_available
            ? "MyClass:4294967295:NamedDescriptor: Named descriptor failed."
            : "MyClass:4294967295:NamedQuery: Named query failed.";
    std::ignore = obj->GetOwnPropertyDescriptor(ctx, v8_str("4294967295"));
    CheckMessage(try_catch, expected);
    std::ignore =
        CompileRun("Object.getOwnPropertyDescriptor(obj, 0xffffffff);");
    CheckMessage(try_catch, expected);
  }

  //
  // Check definer callbacks.
  //
  config.query_should_throw = false;
  config.getter_should_throw = false;
  config.descriptor_should_throw = false;
  {
    v8::Local<v8::Value> value = v8_str("value");
    v8::PropertyDescriptor descriptor(value);

    expected = "MyClass:foo:NamedDefiner: Named definer failed.";
    std::ignore = obj->DefineOwnProperty(ctx, v8_str("foo"), value);
    CheckMessage(try_catch, expected);
    std::ignore = obj->DefineProperty(ctx, v8_str("foo"), descriptor);
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("Object.defineProperty(obj, 'foo', {});");
    CheckMessage(try_catch, expected);

    expected = "MyClass:1:IndexedDefiner: Indexed definer failed.";
    std::ignore = obj->DefineOwnProperty(ctx, v8_str("1"), value);
    CheckMessage(try_catch, expected);
    std::ignore = obj->DefineProperty(ctx, v8_str("1"), descriptor);
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("Object.defineProperty(obj, 1, {});");
    CheckMessage(try_catch, expected);

    expected = "MyClass:4294967294:IndexedDefiner: Indexed definer failed.";
    std::ignore = obj->DefineOwnProperty(ctx, v8_str("4294967294"), value);
    CheckMessage(try_catch, expected);
    std::ignore = obj->DefineProperty(ctx, v8_str("4294967294"), descriptor);
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("Object.defineProperty(obj, 0xfffffffe, {});");
    CheckMessage(try_catch, expected);

    expected = "MyClass:4294967295:NamedDefiner: Named definer failed.";
    std::ignore = obj->DefineOwnProperty(ctx, v8_str("4294967295"), value);
    CheckMessage(try_catch, expected);
    std::ignore = obj->DefineProperty(ctx, v8_str("4294967295"), descriptor);
    CheckMessage(try_catch, expected);
    std::ignore = CompileRun("Object.defineProperty(obj, 0xffffffff, {});");
    CheckMessage(try_catch, expected);
  }
}

// Can't use THREADED_TEST because this test requires setting an exception
// preprocessing callback which might be observable in other tests.
TEST(PreprocessExceptionFromInterceptorsWithoutDescriptorCallback) {
  i::v8_flags.experimental_report_exceptions_from_callbacks = true;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::FunctionTemplate> ctor = v8::FunctionTemplate::New(isolate);
  ctor->SetClassName(v8_str("MyClass"));
  v8::Local<v8::ObjectTemplate> obj_template = ctor->InstanceTemplate();

  isolate->SetExceptionPropagationCallback(PreprocessExceptionTestCallback);

  PreprocessExceptionTestConfig config;

  obj_template->SetHandler(v8::NamedPropertyHandlerConfiguration(
      PETNamedGetter, PETNamedSetter, PETNamedQuery, PETNamedDeleter,
      nullptr,  // enumerator
      PETNamedDefiner,
      nullptr,  // descriptor
      v8::External::New(isolate, &config)));
  obj_template->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      PETIndexedGetter, PETIndexedSetter, PETIndexedQuery, PETIndexedDeleter,
      nullptr,  // enumerator
      PETIndexedDefiner,
      nullptr,  // descriptor
      v8::External::New(isolate, &config)));

  LocalContext env;
  Local<Context> ctx = env.local();
  v8::Local<v8::Object> obj = obj_template->NewInstance(ctx).ToLocalChecked();

  v8::Local<v8::Object> global = ctx->Global();
  global->Set(ctx, v8_str("obj"), obj).FromJust();

  constexpr bool is_descriptor_callback_available = false;
  TestPreprocessExceptionFromInterceptors(isolate, config, ctx, obj,
                                          is_descriptor_callback_available);
}

// Can't use THREADED_TEST because this test requires setting an exception
// preprocessing callback which might be observable in other tests.
TEST(PreprocessExceptionFromInterceptorsWithDescriptorCallback) {
  i::v8_flags.experimental_report_exceptions_from_callbacks = true;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::FunctionTemplate> ctor = v8::FunctionTemplate::New(isolate);
  ctor->SetClassName(v8_str("MyClass"));
  v8::Local<v8::ObjectTemplate> obj_template = ctor->InstanceTemplate();

  isolate->SetExceptionPropagationCallback(PreprocessExceptionTestCallback);

  PreprocessExceptionTestConfig config;

  obj_template->SetHandler(v8::NamedPropertyHandlerConfiguration(
      PETNamedGetter, PETNamedSetter, PETNamedQuery, PETNamedDeleter,
      nullptr,  // enumerator
      PETNamedDefiner, PETNamedDescriptor,
      v8::External::New(isolate, &config)));
  obj_template->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      PETIndexedGetter, PETIndexedSetter, PETIndexedQuery, PETIndexedDeleter,
      nullptr,  // enumerator
      PETIndexedDefiner, PETIndexedDescriptor,
      v8::External::New(isolate, &config)));

  LocalContext env;
  Local<Context> ctx = env.local();
  v8::Local<v8::Object> obj = obj_template->NewInstance(ctx).ToLocalChecked();

  v8::Local<v8::Object> global = ctx->Global();
  global->Set(ctx, v8_str("obj"), obj).FromJust();

  constexpr bool is_descriptor_callback_available = true;
  TestPreprocessExceptionFromInterceptors(isolate, config, ctx, obj,
                                          is_descriptor_callback_available);
}

namespace {

template <typename T>
Local<Object> BuildWrappedObject(v8::Isolate* isolate, T* data) {
  auto templ = v8::ObjectTemplate::New(isolate);
  templ->SetInternalFieldCount(1);
  auto instance =
      templ->NewInstance(isolate->GetCurrentContext()).ToLocalChecked();
  instance->SetAlignedPointerInInternalField(0, data);
  return instance;
}


template <typename T>
T* GetWrappedObject(Local<Value> data) {
  return reinterpret_cast<T*>(
      Object::Cast(*data)->GetAlignedPointerFromInternalField(0));
}


struct AccessCheckData {
  int count;
  bool result;
};

struct ShouldInterceptData {
  int value;
  bool should_intercept;
};

v8::Intercepted ShouldNamedInterceptor(
    Local<Name> name, const v8::PropertyCallbackInfo<Value>& info) {
  CheckReturnValue(info, FUNCTION_ADDR(ShouldNamedInterceptor));
  auto data = GetWrappedObject<ShouldInterceptData>(info.Data());
  if (!data->should_intercept) return v8::Intercepted::kNo;
  // Side effects are allowed only when the property is present or throws.
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(data->value));
  return v8::Intercepted::kYes;
}

v8::Intercepted ShouldIndexedInterceptor(
    uint32_t, const v8::PropertyCallbackInfo<Value>& info) {
  CheckReturnValue(info, FUNCTION_ADDR(ShouldIndexedInterceptor));
  auto data = GetWrappedObject<ShouldInterceptData>(info.Data());
  if (!data->should_intercept) return v8::Intercepted::kNo;
  // Side effects are allowed only when the property is present or throws.
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(data->value));
  return v8::Intercepted::kYes;
}

}  // namespace

THREADED_TEST(NonMaskingInterceptorOwnProperty) {
  auto isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  LocalContext context;

  ShouldInterceptData intercept_data;
  intercept_data.value = 239;
  intercept_data.should_intercept = true;

  auto interceptor_templ = v8::ObjectTemplate::New(isolate);
  v8::NamedPropertyHandlerConfiguration conf(ShouldNamedInterceptor);
  conf.flags = v8::PropertyHandlerFlags::kNonMasking;
  conf.data = BuildWrappedObject<ShouldInterceptData>(isolate, &intercept_data);
  interceptor_templ->SetHandler(conf);

  auto interceptor =
      interceptor_templ->NewInstance(context.local()).ToLocalChecked();
  context->Global()
      ->Set(context.local(), v8_str("obj"), interceptor)
      .FromJust();

  ExpectInt32("obj.whatever", 239);

  CompileRun("obj.whatever = 4;");

  // obj.whatever exists, thus it is not affected by the non-masking
  // interceptor.
  ExpectInt32("obj.whatever", 4);

  CompileRun("delete obj.whatever;");
  ExpectInt32("obj.whatever", 239);
}


THREADED_TEST(NonMaskingInterceptorPrototypeProperty) {
  auto isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  LocalContext context;

  ShouldInterceptData intercept_data;
  intercept_data.value = 239;
  intercept_data.should_intercept = true;

  auto interceptor_templ = v8::ObjectTemplate::New(isolate);
  v8::NamedPropertyHandlerConfiguration conf(ShouldNamedInterceptor);
  conf.flags = v8::PropertyHandlerFlags::kNonMasking;
  conf.data = BuildWrappedObject<ShouldInterceptData>(isolate, &intercept_data);
  interceptor_templ->SetHandler(conf);

  auto interceptor =
      interceptor_templ->NewInstance(context.local()).ToLocalChecked();
  context->Global()
      ->Set(context.local(), v8_str("obj"), interceptor)
      .FromJust();

  ExpectInt32("obj.whatever", 239);

  CompileRun("obj.__proto__ = {'whatever': 4};");
  ExpectInt32("obj.whatever", 4);

  CompileRun("delete obj.__proto__.whatever;");
  ExpectInt32("obj.whatever", 239);
}


THREADED_TEST(NonMaskingInterceptorPrototypePropertyIC) {
  auto isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  LocalContext context;

  ShouldInterceptData intercept_data;
  intercept_data.value = 239;
  intercept_data.should_intercept = true;

  auto interceptor_templ = v8::ObjectTemplate::New(isolate);
  v8::NamedPropertyHandlerConfiguration conf(ShouldNamedInterceptor);
  conf.flags = v8::PropertyHandlerFlags::kNonMasking;
  conf.data = BuildWrappedObject<ShouldInterceptData>(isolate, &intercept_data);
  interceptor_templ->SetHandler(conf);

  auto interceptor =
      interceptor_templ->NewInstance(context.local()).ToLocalChecked();
  context->Global()
      ->Set(context.local(), v8_str("obj"), interceptor)
      .FromJust();

  CompileRun(
      "outer = {};"
      "outer.__proto__ = obj;"
      "function f(obj) {"
      "  var x;"
      "  for (var i = 0; i < 4; i++) {"
      "    x = obj.whatever;"
      "  }"
      "  return x;"
      "}");

  // Receiver == holder.
  CompileRun("obj.__proto__ = null;");
  ExpectInt32("f(obj)", 239);
  ExpectInt32("f(outer)", 239);

  // Receiver != holder.
  CompileRun("Object.setPrototypeOf(obj, {});");
  ExpectInt32("f(obj)", 239);
  ExpectInt32("f(outer)", 239);

  // Masked value on prototype.
  CompileRun("obj.__proto__.whatever = 4;");
  CompileRun("obj.__proto__.__proto__ = { 'whatever' : 5 };");
  ExpectInt32("f(obj)", 4);
  ExpectInt32("f(outer)", 4);

  // Masked value on prototype prototype.
  CompileRun("delete obj.__proto__.whatever;");
  ExpectInt32("f(obj)", 5);
  ExpectInt32("f(outer)", 5);

  // Reset.
  CompileRun("delete obj.__proto__.__proto__.whatever;");
  ExpectInt32("f(obj)", 239);
  ExpectInt32("f(outer)", 239);

  // Masked value on self.
  CompileRun("obj.whatever = 4;");
  ExpectInt32("f(obj)", 4);
  ExpectInt32("f(outer)", 4);

  // Reset.
  CompileRun("delete obj.whatever;");
  ExpectInt32("f(obj)", 239);
  ExpectInt32("f(outer)", 239);

  CompileRun("outer.whatever = 4;");
  ExpectInt32("f(obj)", 239);
  ExpectInt32("f(outer)", 4);
}

namespace {

v8::Intercepted ConcatNamedPropertyGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  info.GetReturnValue().Set(
      // Return the property name concatenated with itself.
      String::Concat(info.GetIsolate(), name.As<String>(), name.As<String>()));
  return v8::Intercepted::kYes;
}

v8::Intercepted ConcatIndexedPropertyGetter(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  info.GetReturnValue().Set(
      // Return the double value of the index.
      v8_num(index + index));
  return v8::Intercepted::kYes;
}

void EnumCallbackWithNames(const v8::PropertyCallbackInfo<v8::Array>& info) {
  ApiTestFuzzer::Fuzz();
  v8::Local<v8::Array> result = v8::Array::New(info.GetIsolate(), 4);
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  CHECK(
      result
          ->Set(context, v8::Integer::New(info.GetIsolate(), 0), v8_str("foo"))
          .FromJust());
  CHECK(
      result
          ->Set(context, v8::Integer::New(info.GetIsolate(), 1), v8_str("bar"))
          .FromJust());
  CHECK(
      result
          ->Set(context, v8::Integer::New(info.GetIsolate(), 2), v8_str("baz"))
          .FromJust());
  CHECK(
      result->Set(context, v8::Integer::New(info.GetIsolate(), 3), v8_str("10"))
          .FromJust());

  //  Create a holey array.
  CHECK(result->Delete(context, v8::Integer::New(info.GetIsolate(), 1))
            .FromJust());
  info.GetReturnValue().Set(result);
}

void EnumCallbackWithIndices(const v8::PropertyCallbackInfo<v8::Array>& info) {
  ApiTestFuzzer::Fuzz();
  v8::Local<v8::Array> result = v8::Array::New(info.GetIsolate(), 4);
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();

  CHECK(result->Set(context, v8::Integer::New(info.GetIsolate(), 0), v8_num(10))
            .FromJust());
  CHECK(result->Set(context, v8::Integer::New(info.GetIsolate(), 1), v8_num(11))
            .FromJust());
  CHECK(result->Set(context, v8::Integer::New(info.GetIsolate(), 2), v8_num(12))
            .FromJust());
  CHECK(result->Set(context, v8::Integer::New(info.GetIsolate(), 3), v8_num(14))
            .FromJust());

  //  Create a holey array.
  CHECK(result->Delete(context, v8::Integer::New(info.GetIsolate(), 1))
            .FromJust());
  info.GetReturnValue().Set(result);
}

v8::Intercepted RestrictiveNamedQuery(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  // Only "foo" is enumerable.
  if (v8_str("foo")
          ->Equals(info.GetIsolate()->GetCurrentContext(), property)
          .FromJust()) {
    info.GetReturnValue().Set(v8::None);
    return v8::Intercepted::kYes;
  }
  info.GetReturnValue().Set(v8::DontEnum);
  return v8::Intercepted::kYes;
}

v8::Intercepted RestrictiveIndexedQuery(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  // Only index 2 and 12 are enumerable.
  if (index == 2 || index == 12) {
    info.GetReturnValue().Set(v8::None);
    return v8::Intercepted::kYes;
  }
  info.GetReturnValue().Set(v8::DontEnum);
  return v8::Intercepted::kYes;
}
}  // namespace

// Regression test for V8 bug 6627.
// Object.keys() must return enumerable keys only.
THREADED_TEST(EnumeratorsAndUnenumerableNamedProperties) {
  // The enumerator interceptor returns a list
  // of items which are filtered according to the
  // properties defined in the query interceptor.
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::NamedPropertyHandlerConfiguration(
      Co
```