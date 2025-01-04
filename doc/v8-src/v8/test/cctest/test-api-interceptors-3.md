Response: The user wants a summary of the C++ code provided, which is part 4 of a larger file. The code focuses on testing the functionality of interceptors in the V8 JavaScript engine's C++ API. It seems to cover various aspects of interceptors, including how they interact with JavaScript features like property access, enumeration, and exception handling.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Topic:** The file name and the presence of terms like `SetHandler`, `NamedPropertyHandlerConfiguration`, `IndexedPropertyHandlerConfiguration`, `PropertyCallbackInfo`, etc., clearly indicate the subject is V8 API interceptors.

2. **Scan for Key Functionality Areas:** Look for distinct sets of tests or helper functions that address different aspects of interceptors. The code is well-organized with descriptive test names. Notice sections related to:
    * Failing interceptors during enumeration (`IndexedEnumeratorException`, `NamedPropertyEnumeratorException`).
    * Preprocessing exceptions from interceptors (`PreprocessExceptionTestCallback`, `TestPreprocessExceptionFromInterceptors`).
    * Non-masking interceptors (`NonMaskingInterceptorOwnProperty`, `NonMaskingInterceptorPrototypeProperty`, `NonMaskingInterceptorPrototypePropertyIC`).
    * Interceptors and enumeration (`EnumeratorsAndUnenumerableNamedProperties`, `EnumeratorsAndUnenumerableIndexedProperties`).
    * Interceptors and `for...in` loops (`EnumeratorsAndForIn`).
    * Interceptors and global eval (`NonMaskingInterceptorGlobalEvalRegression`).
    * Edge cases and regressions (`Regress609134Interceptor`, `Regress42204611`).

3. **Summarize Each Functionality Area:**  For each identified area, concisely describe what the code is testing or demonstrating. Use the test names and the code itself as clues. For example:
    * `IndexedEnumeratorException`: Tests how a failing indexed interceptor affects enumeration (`for...in`, `Object.keys`).
    * `PreprocessExceptionTestCallback`:  Sets up a callback to modify exception messages originating from interceptors. The related test (`TestPreprocessExceptionFromInterceptors`) verifies this mechanism for different interceptor types and JavaScript operations.
    * `NonMaskingInterceptor`: Explores the behavior of interceptors with the `kNonMasking` flag, showing how they interact with own properties and prototype properties.

4. **Look for JavaScript Examples:** The prompt specifically asks for JavaScript examples if there's a connection. Many tests directly execute JavaScript code using `CompileRun`. Extract these snippets that illustrate the interceptor's effect. For instance, in the `IndexedEnumeratorException` test, the `for...in` and `Object.keys` calls demonstrate how the failing interceptor causes an exception.

5. **Synthesize the Overall Functionality:** Combine the summaries of individual areas into a cohesive description of the file's purpose. Emphasize that it's a test file and its focus is on verifying the behavior of V8 API interceptors.

6. **Address the "Part 4 of 4" Information:** Acknowledge that this is the final part, suggesting it likely completes the set of interceptor tests.

7. **Refine and Organize:** Ensure the summary is clear, concise, and well-organized. Use bullet points or similar formatting to improve readability. Ensure the JavaScript examples are correctly associated with the corresponding functionality.

**Self-Correction/Refinement during the process:**

* Initially, I might just list the test names. However, the prompt asks for functionality, so I need to go beyond just naming the tests and explain *what* each test is doing.
* I might initially focus too much on the C++ details. The prompt also asks for the relationship to JavaScript, so I need to actively look for the JavaScript interactions within the C++ test code.
* I need to be careful about accurately describing the purpose of flags like `kNonMasking`. Referring to the V8 documentation or prior knowledge is helpful here.
* The "Part 4 of 4" detail indicates I shouldn't expect further continuation of these specific tests in other files.

By following these steps, and iteratively refining the summary, I can arrive at a comprehensive and accurate description of the provided C++ code and its relationship to JavaScript functionality.
这是 `v8/test/cctest/test-api-interceptors.cc` 文件的第四部分，主要功能是**继续测试 V8 JavaScript 引擎 C++ API 中 Interceptors（拦截器）的各种行为和特性，特别是涉及到更复杂的使用场景、错误处理、以及与 JavaScript 特性的交互。**

延续前几部分，这部分测试涵盖了以下几个关键方面：

**1. 拦截器抛出异常时的行为:**

*   **`GetOwnPropertyNamesWithIndexedInterceptorExceptions_regress4026` 和 `GetOwnPropertyNamesWithNamedInterceptorExceptions_regress4026`:**  测试在执行 `for...in` 循环或 `Object.keys()` 时，如果索引或命名属性的枚举器拦截器抛出异常，V8 引擎是否能够正确捕获并处理这些异常。示例中，拦截器故意抛出带有特定数值的异常，然后 JavaScript 代码捕获并验证异常值。

*   **`PreprocessExceptionFromInterceptorsWithoutDescriptorCallback` 和 `PreprocessExceptionFromInterceptorsWithDescriptorCallback`:**  深入测试当拦截器抛出异常时，V8 的异常预处理回调机制。它设置了一个全局的异常预处理回调函数 (`PreprocessExceptionTestCallback`)，该函数可以修改异常信息。测试验证了在各种操作（如获取属性、设置属性、删除属性、定义属性等）中，不同类型的拦截器（getter, setter, query, deleter, definer, descriptor）抛出异常时，预处理回调是否被正确调用，以及最终捕获的异常信息是否符合预期。

**2. 非掩盖拦截器 (`NonMasking` Interceptors):**

*   **`NonMaskingInterceptorOwnProperty`:** 测试带有 `kNonMasking` 标志的命名属性拦截器如何与对象的自有属性交互。即使对象本身已经有了同名属性，非掩盖拦截器仍然会被调用。
*   **`NonMaskingInterceptorPrototypeProperty` 和 `NonMaskingInterceptorPrototypePropertyIC`:** 测试非掩盖拦截器如何与原型链上的属性交互。即使属性存在于对象的原型链上，非掩盖拦截器仍然会被调用。`NonMaskingInterceptorPrototypePropertyIC` 还涉及到内联缓存 (Inline Cache, IC) 的优化。

**3. 拦截器与属性枚举 (`Enumerators`) 的交互:**

*   **`EnumeratorsAndUnenumerableNamedProperties` 和 `EnumeratorsAndUnenumerableNamedPropertiesWithoutSet`:** 测试命名属性拦截器中的枚举器回调 (`EnumCallbackWithNames`) 如何与查询拦截器 (`RestrictiveNamedQuery` 或 `QueryInterceptorForFoo`) 协同工作，来控制哪些属性是可枚举的。`Object.getOwnPropertyNames()`, `Object.keys()`, `Object.entries()`, `Object.values()` 等方法会受到影响。
*   **`EnumeratorsAndUnenumerableIndexedPropertiesArgumentsElements` 和 `EnumeratorsAndUnenumerableIndexedProperties`:**  类似于命名属性，测试索引属性拦截器中的枚举器回调 (`SloppyArgsIndexedPropertyEnumerator` 或 `EnumCallbackWithIndices`) 如何与查询拦截器 (`RestrictiveIndexedQuery`) 协同工作，控制可枚举的索引属性。
*   **`EnumeratorsAndForIn`:**  测试拦截器如何影响 `for...in` 循环的遍历行为，确保只有可枚举的属性会被遍历。

**4. 更复杂的拦截器使用场景:**

*   **`NonMaskingInterceptorGlobalEvalRegression`:**  这是一个回归测试，用于验证非掩盖拦截器在 `eval()` 函数中的行为是否正确，避免出现全局作用域中的意外影响。它模拟了一个使用拦截器来访问数据库的场景。

**5. 回归测试，修复特定 Bug:**

*   **`Regress609134Interceptor`:**  针对一个特定的 Bug (609134) 的回归测试，确保在特定情况下（例如修改 `Number.prototype.__proto__`）拦截器能够正确工作。
*   **`Regress42204611`:**  针对另一个 Bug (42204611) 的回归测试，涉及到 `Object.defineProperty` 和非掩盖拦截器的交互，验证了 getter、setter 和 definer 拦截器在定义属性时的调用顺序和次数。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这部分代码与 JavaScript 的核心功能紧密相关，因为它测试的是 JavaScript 对象属性的访问、修改、枚举以及异常处理机制，而这些机制可以通过 C++ API 的拦截器进行自定义。

以下是一些与代码片段相关的 JavaScript 示例：

*   **枚举器异常 (Indexed/Named):**

    ```javascript
    const obj = {};
    // ... (C++ 代码设置 obj 的拦截器) ...

    try {
      for (let key in obj) {
        console.log(key);
      }
    } catch (e) {
      console.error("Caught exception:", e); // e 将是 C++ 代码中抛出的 42 或 43
    }

    try {
      const keys = Object.keys(obj);
      console.log(keys);
    } catch (e) {
      console.error("Caught exception:", e); // e 将是 C++ 代码中抛出的 42 或 43
    }
    ```

*   **异常预处理:**

    ```javascript
    const obj = {};
    // ... (C++ 代码设置 obj 的拦截器和异常预处理回调) ...

    try {
      obj.foo; // 或 obj[1] 等触发拦截器的操作
    } catch (e) {
      console.error(e.message); // 异常消息会被 C++ 代码中的 PreprocessExceptionTestCallback 修改
    }
    ```

*   **非掩盖拦截器:**

    ```javascript
    const obj = {};
    // ... (C++ 代码设置 obj 的非掩盖拦截器) ...

    obj.whatever = 10; // 即使设置了自有属性，拦截器仍然会影响获取操作
    console.log(obj.whatever);

    delete obj.whatever;
    console.log(obj.whatever); // 再次触发拦截器

    const proto = { whatever: 20 };
    Object.setPrototypeOf(obj, proto);
    console.log(obj.whatever); // 仍然会触发拦截器
    ```

*   **属性枚举:**

    ```javascript
    const obj = {};
    // ... (C++ 代码设置 obj 的拦截器和枚举器) ...

    for (let key in obj) {
      console.log(key, obj[key]); // 只会遍历可枚举的属性
    }

    console.log(Object.keys(obj)); // 只会返回可枚举的键
    console.log(Object.getOwnPropertyNames(obj)); // 返回所有自有属性名，包括不可枚举的
    ```

总的来说，这部分测试用例深入探讨了 V8 引擎拦截器机制的复杂性和健壮性，确保了拦截器能够在各种场景下正确工作，并且与 JavaScript 的核心特性（如属性访问、枚举和异常处理）良好地集成。作为最后一部分，它很可能涵盖了之前部分未涉及的更边缘化或更细致的测试场景。

Prompt: 
```
这是目录为v8/test/cctest/test-api-interceptors.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
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
      ConcatNamedPropertyGetter, nullptr, RestrictiveNamedQuery, nullptr,
      EnumCallbackWithNames));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            obj->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  ExpectInt32("Object.getOwnPropertyNames(obj).length", 3);
  ExpectString("Object.getOwnPropertyNames(obj)[0]", "foo");
  ExpectString("Object.getOwnPropertyNames(obj)[1]", "baz");
  ExpectString("Object.getOwnPropertyNames(obj)[2]", "10");

  ExpectTrue("Object.getOwnPropertyDescriptor(obj, 'foo').enumerable");
  ExpectFalse("Object.getOwnPropertyDescriptor(obj, 'baz').enumerable");

  ExpectInt32("Object.entries(obj).length", 1);
  ExpectString("Object.entries(obj)[0][0]", "foo");
  ExpectString("Object.entries(obj)[0][1]", "foofoo");

  ExpectInt32("Object.keys(obj).length", 1);
  ExpectString("Object.keys(obj)[0]", "foo");

  ExpectInt32("Object.values(obj).length", 1);
  ExpectString("Object.values(obj)[0]", "foofoo");
}

namespace {
v8::Intercepted QueryInterceptorForFoo(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  // Don't intercept anything except "foo."
  if (!v8_str("foo")
           ->Equals(info.GetIsolate()->GetCurrentContext(), property)
           .FromJust()) {
    return v8::Intercepted::kNo;
  }
  // "foo" is enumerable.
  info.GetReturnValue().Set(v8::PropertyAttribute::None);
  return v8::Intercepted::kYes;
}
}  // namespace

// Test that calls to the query interceptor are independent of each
// other.
THREADED_TEST(EnumeratorsAndUnenumerableNamedPropertiesWithoutSet) {
  // The enumerator interceptor returns a list
  // of items which are filtered according to the
  // properties defined in the query interceptor.
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::NamedPropertyHandlerConfiguration(
      ConcatNamedPropertyGetter, nullptr, QueryInterceptorForFoo, nullptr,
      EnumCallbackWithNames));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            obj->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  ExpectInt32("Object.getOwnPropertyNames(obj).length", 3);
  ExpectString("Object.getOwnPropertyNames(obj)[0]", "foo");
  ExpectString("Object.getOwnPropertyNames(obj)[1]", "baz");
  ExpectString("Object.getOwnPropertyNames(obj)[2]", "10");

  ExpectTrue("Object.getOwnPropertyDescriptor(obj, 'foo').enumerable");
  ExpectInt32("Object.keys(obj).length", 1);
}

THREADED_TEST(EnumeratorsAndUnenumerableIndexedPropertiesArgumentsElements) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      ConcatIndexedPropertyGetter, nullptr, RestrictiveIndexedQuery, nullptr,
      SloppyArgsIndexedPropertyEnumerator));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            obj->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  ExpectInt32("Object.getOwnPropertyNames(obj).length", 4);
  ExpectString("Object.getOwnPropertyNames(obj)[0]", "0");
  ExpectString("Object.getOwnPropertyNames(obj)[1]", "1");
  ExpectString("Object.getOwnPropertyNames(obj)[2]", "2");
  ExpectString("Object.getOwnPropertyNames(obj)[3]", "3");

  ExpectTrue("Object.getOwnPropertyDescriptor(obj, '2').enumerable");

  ExpectInt32("Object.entries(obj).length", 1);
  ExpectString("Object.entries(obj)[0][0]", "2");
  ExpectInt32("Object.entries(obj)[0][1]", 4);

  ExpectInt32("Object.keys(obj).length", 1);
  ExpectString("Object.keys(obj)[0]", "2");

  ExpectInt32("Object.values(obj).length", 1);
  ExpectInt32("Object.values(obj)[0]", 4);
}

THREADED_TEST(EnumeratorsAndUnenumerableIndexedProperties) {
  // The enumerator interceptor returns a list
  // of items which are filtered according to the
  // properties defined in the query interceptor.
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      ConcatIndexedPropertyGetter, nullptr, RestrictiveIndexedQuery, nullptr,
      EnumCallbackWithIndices));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            obj->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  ExpectInt32("Object.getOwnPropertyNames(obj).length", 3);
  ExpectString("Object.getOwnPropertyNames(obj)[0]", "10");
  ExpectString("Object.getOwnPropertyNames(obj)[1]", "12");
  ExpectString("Object.getOwnPropertyNames(obj)[2]", "14");

  ExpectFalse("Object.getOwnPropertyDescriptor(obj, '10').enumerable");
  ExpectTrue("Object.getOwnPropertyDescriptor(obj, '12').enumerable");

  ExpectInt32("Object.entries(obj).length", 1);
  ExpectString("Object.entries(obj)[0][0]", "12");
  ExpectInt32("Object.entries(obj)[0][1]", 24);

  ExpectInt32("Object.keys(obj).length", 1);
  ExpectString("Object.keys(obj)[0]", "12");

  ExpectInt32("Object.values(obj).length", 1);
  ExpectInt32("Object.values(obj)[0]", 24);
}

THREADED_TEST(EnumeratorsAndForIn) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::NamedPropertyHandlerConfiguration(
      ConcatNamedPropertyGetter, nullptr, RestrictiveNamedQuery, nullptr,
      NamedEnum));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            obj->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  ExpectInt32("Object.getOwnPropertyNames(obj).length", 3);
  ExpectString("Object.getOwnPropertyNames(obj)[0]", "foo");

  ExpectTrue("Object.getOwnPropertyDescriptor(obj, 'foo').enumerable");

  CompileRun(
      "let concat = '';"
      "for(var prop in obj) {"
      "  concat += `key:${prop}:value:${obj[prop]}`;"
      "}");

  // Check that for...in only iterates over enumerable properties.
  ExpectString("concat", "key:foo:value:foofoo");
}

namespace {

v8::Intercepted DatabaseGetter(Local<Name> name,
                               const v8::PropertyCallbackInfo<Value>& info) {
  auto context = info.GetIsolate()->GetCurrentContext();
  v8::MaybeLocal<Value> maybe_db =
      info.HolderV2()->GetRealNamedProperty(context, v8_str("db"));
  if (maybe_db.IsEmpty()) return v8::Intercepted::kNo;
  Local<v8::Object> db = maybe_db.ToLocalChecked().As<v8::Object>();
  if (!db->Has(context, name).FromJust()) return v8::Intercepted::kNo;

  // Side effects are allowed only when the property is present or throws.
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(db->Get(context, name).ToLocalChecked());
  return v8::Intercepted::kYes;
}

v8::Intercepted DatabaseSetter(Local<Name> name, Local<Value> value,
                               const v8::PropertyCallbackInfo<void>& info) {
  auto context = info.GetIsolate()->GetCurrentContext();
  if (name->Equals(context, v8_str("db")).FromJust())
    return v8::Intercepted::kNo;

  // Side effects are allowed only when the property is present or throws.
  ApiTestFuzzer::Fuzz();
  Local<v8::Object> db = info.HolderV2()
                             ->GetRealNamedProperty(context, v8_str("db"))
                             .ToLocalChecked()
                             .As<v8::Object>();
  db->Set(context, name, value).FromJust();
  return v8::Intercepted::kYes;
}

}  // namespace


THREADED_TEST(NonMaskingInterceptorGlobalEvalRegression) {
  auto isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  LocalContext context;

  auto interceptor_templ = v8::ObjectTemplate::New(isolate);
  v8::NamedPropertyHandlerConfiguration conf(DatabaseGetter, DatabaseSetter);
  conf.flags = v8::PropertyHandlerFlags::kNonMasking;
  interceptor_templ->SetHandler(conf);

  context->Global()
      ->Set(context.local(), v8_str("intercepted_1"),
            interceptor_templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  context->Global()
      ->Set(context.local(), v8_str("intercepted_2"),
            interceptor_templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  // Init dbs.
  CompileRun(
      "intercepted_1.db = {};"
      "intercepted_2.db = {};");

  ExpectInt32(
      "var obj = intercepted_1;"
      "obj.x = 4;"
      "eval('obj.x');"
      "eval('obj.x');"
      "eval('obj.x');"
      "obj = intercepted_2;"
      "obj.x = 9;"
      "eval('obj.x');",
      9);
}

namespace {
v8::Intercepted CheckReceiver(Local<Name> name,
                              const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(info.This()->IsObject());
  return v8::Intercepted::kNo;
}
}  // namespace

TEST(Regress609134Interceptor) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  auto fun_templ = v8::FunctionTemplate::New(isolate);
  fun_templ->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(CheckReceiver));

  CHECK(env->Global()
            ->Set(env.local(), v8_str("Fun"),
                  fun_templ->GetFunction(env.local()).ToLocalChecked())
            .FromJust());

  CompileRun(
      "var f = new Fun();"
      "Number.prototype.__proto__ = f;"
      "var a = 42;"
      "for (var i = 0; i<3; i++) { a.foo; }");
}

namespace {

v8::Intercepted Regress42204611_Getter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  std::vector<std::string>* calls = reinterpret_cast<std::vector<std::string>*>(
      info.Data().As<v8::External>()->Value());

  calls->push_back("getter");
  return v8::Intercepted::kNo;
}
v8::Intercepted Regress42204611_Setter(
    Local<Name> name, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  std::vector<std::string>* calls = reinterpret_cast<std::vector<std::string>*>(
      info.Data().As<v8::External>()->Value());

  calls->push_back("setter");
  return v8::Intercepted::kNo;
}
v8::Intercepted Regress42204611_Definer(
    Local<Name> name, const v8::PropertyDescriptor& descriptor,
    const v8::PropertyCallbackInfo<void>& info) {
  std::vector<std::string>* calls = reinterpret_cast<std::vector<std::string>*>(
      info.Data().As<v8::External>()->Value());

  calls->push_back("definer");
  return v8::Intercepted::kNo;
}

}  // namespace

// Regression test for crbug.com/42204611
THREADED_TEST(Regress42204611) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  std::vector<std::string> calls;
  Local<v8::External> calls_ext = v8::External::New(CcTest::isolate(), &calls);

  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  object_template->SetHandler(v8::NamedPropertyHandlerConfiguration(
      Regress42204611_Getter, Regress42204611_Setter, nullptr, nullptr, nullptr,
      Regress42204611_Definer, calls_ext,
      static_cast<v8::PropertyHandlerFlags>(
          static_cast<int>(v8::PropertyHandlerFlags::kNonMasking) |
          static_cast<int>(v8::PropertyHandlerFlags::kHasNoSideEffect))));

  v8::Local<v8::Context> ctx =
      v8::Context::New(CcTest::isolate(), nullptr, object_template);

  {
    v8::Context::Scope scope(ctx);
    CompileRun(
        "Object.defineProperty(globalThis, 'key', {"
        "  value: 9, enumerable: true, configurable: true, writable: true"
        "})");
  }

  // We should intercept:
  //   1. The getter when getting the current property attributes,
  //   2. The definer when trying to intercept the define itself,
  //   3. The setter when applying the property descriptor.
  CHECK_EQ(calls, std::vector<std::string>({"getter", "definer", "setter"}));
}

"""


```