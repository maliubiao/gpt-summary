Response: My goal is to summarize the functionality of the C++ code snippet and illustrate its interaction with JavaScript. Here's my thinking process:

1. **Understand the Context:** The code is part 6 of 18 from `v8/test/cctest/test-api.cc`. This immediately tells me it's a C++ test file for the V8 JavaScript engine's C++ API. The `cctest` directory reinforces this.

2. **Identify Key Themes:** I scanned the code for recurring patterns and keywords. Several themes emerge quickly:
    * **`THREADED_TEST`:** This signifies individual test cases.
    * **`LocalContext`:** Indicates the creation and manipulation of V8 JavaScript contexts within the tests.
    * **`v8::String::NewFromUtf8Literal`:**  Suggests tests related to string creation and handling, particularly with UTF-8 encoding.
    * **`Utf16Helper`:**  Further confirms a focus on UTF-16 encoding.
    * **`SameSymbol`:**  Points to testing the identity and internalization of strings (symbols).
    * **Surrogate pairs (e.g., `\xED\xA0\x81\xED\xB0\x87`):**  Specifically tests UTF-16 encoding with characters outside the Basic Multilingual Plane (BMP).
    * **`ToArrayIndex`:** Tests the conversion of strings and numbers to valid array indices.
    * **`v8::Exception::...Error`:**  Deals with the creation and handling of JavaScript exceptions.
    * **`TryCatch`:**  Confirms testing of exception handling.
    * **Property accessors (getters/setters):**  Tests the behavior of custom property accessors defined in C++.
    * **`AddMessageListener`, `RemoveMessageListeners`:**  Indicates testing of uncaught exception handling and message reporting.
    * **Security checks:** A significant portion deals with testing security mechanisms in V8, particularly cross-context access control. Keywords like `SetSecurityToken`, `AccessCheckCallback` are crucial here.
    * **Context manipulation (`Context::New`, `Enter`, `Exit`, `DetachGlobal`):** Tests the creation and management of V8 contexts, including detaching and reusing global objects.
    * **`ObjectTemplate`, `InstanceTemplate`:** Relates to the creation of object and function templates, and their instances.
    * **`GetOwnPropertyNames`:** Tests the retrieval of own property names of objects.
    * **Shadow objects and interceptors:** Tests the interaction of native C++ code with JavaScript object property access through interceptors.

3. **Group Related Tests:** I then grouped the tests based on these themes to create a coherent summary. For instance, all tests involving `Utf16Helper`, surrogate pairs, and UTF-8/UTF-16 conversion are grouped together. Similarly, all tests involving `SetSecurityToken`, `AccessCheckCallback`, and context manipulation are grouped.

4. **Infer Functionality:** Based on the test names and the operations performed within them, I inferred the functionality being tested. For example, `Utf16Symbol` tests the creation and comparison of internalized strings with UTF-16 characters. `SecurityHandler` and `SecurityChecks` verify that cross-context access is properly restricted based on security tokens.

5. **Identify JavaScript Relevance:**  For each functional area, I considered how it relates to JavaScript. String manipulation, exception handling, and object property access are core JavaScript concepts. Security and context management are important for isolating JavaScript code and preventing unintended interactions.

6. **Construct JavaScript Examples:** For the key functional areas with JavaScript relevance, I crafted simple JavaScript examples to illustrate the concepts. The examples aim to be clear and directly related to the C++ code's purpose. For example, for the UTF-16 tests, I showed how to create strings with surrogate pairs in JavaScript and check their length and character codes. For security checks, I demonstrated how accessing properties across different security contexts can fail.

7. **Structure the Summary:** I organized the summary logically, starting with general string handling and moving to more complex topics like security and context management. I made sure to clearly label the different functional areas and provide concise explanations.

8. **Address the "Part 6 of 18" Instruction:**  I explicitly mentioned that this is part 6 and that the file focuses on testing the V8 C++ API, particularly features related to string handling, exceptions, security, and context management. This provides the necessary context as requested.

9. **Review and Refine:** Finally, I reviewed the summary and examples for clarity, accuracy, and completeness, ensuring they directly relate to the provided C++ code. I tried to use clear and concise language, avoiding jargon where possible, while still maintaining technical accuracy. I ensured the examples were runnable JavaScript.

By following these steps, I was able to generate a comprehensive summary of the C++ code's functionality and its relationship to JavaScript, along with illustrative JavaScript examples.
文件 `v8/test/cctest/test-api.cc` 的第 6 部分主要集中在测试 V8 JavaScript 引擎的 C++ API 中与以下功能相关的部分：

**主要功能归纳:**

1. **UTF-16 字符串处理:**
   - 测试使用 UTF-8 编码创建包含 UTF-16 字符（包括代理对）的字符串。
   - 验证字符串的长度和字符编码是否正确。
   - 测试内部化字符串（Symbols）的处理，确保相同的 UTF-8 字符串被内部化为相同的 Symbol 对象。
   - 测试从 UTF-8 缓冲区创建 UTF-16 字符串，包括处理不完整的 UTF-8 序列的情况。
   - 测试 `String::Value` 和 `String::ValueView` 在处理包含多字节 UTF-8 字符的字符串时的行为。

2. **数组索引转换 (`ToArrayIndex`):**
   - 测试将字符串和数字转换为合法的数组索引的方法。
   - 验证各种输入（正数、负数、非数字字符串、大数等）的转换结果。

3. **异常处理 (`ErrorConstruction`, `ExceptionCreateMessageLength`, `ApiUncaughtException`, `ExceptionInNativeScript`):**
   - 测试使用 C++ API 创建各种 JavaScript 异常对象（`RangeError`, `ReferenceError`, `SyntaxError`, `TypeError`, `Error`）。
   - 验证创建的异常对象是否包含正确的消息。
   - 测试捕获和处理 JavaScript 异常的情况，包括处理未捕获的异常。
   - 测试在原生 C++ 代码中调用的 JavaScript 代码抛出异常时的处理，并验证异常信息的正确性。

4. **属性访问控制和安全 (`DeleteAccessor`, `SecurityHandler`, `SecurityChecks`, `SecurityChecksForPrototypeChain`, `SecurityTestGCAllowed`, `CrossDomainDelete`, `CrossDomainPropertyIsEnumerable`, `CrossDomainFor`, `CrossDomainForInOnPrototype`, `ContextDetachGlobal`, `DetachGlobal`, `DetachedAccesses`, `AccessControl`, `AccessControlES5`, `Regress470113`, `CrossDomainAccessors`, `AccessControlIC`):**
   - 测试使用 C++ API 定义属性访问器（getter/setter）的能力。
   - 测试 V8 的安全模型，特别是跨上下文访问控制。
   - 验证在不同安全上下文中的对象之间的属性访问是否受到限制。
   - 测试 `SetAccessCheckCallback` 的功能，用于控制跨上下文的对象访问。
   - 测试在跨域访问时，`delete` 操作、`propertyIsEnumerable` 方法和 `for...in` 循环的行为。
   - 测试 `Context::DetachGlobal` 的功能，用于分离上下文的全局对象，并验证分离后的行为。
   - 测试在全局对象被分离后，之前存在的绑定和访问器的行为。

5. **上下文管理 (`ContextDetachGlobal`, `DetachGlobal`, `DetachedAccesses`, `ContextScriptExecutionCallback`):**
   - 测试创建、进入、退出和分离 V8 JavaScript 上下文的功能。
   - 验证在不同上下文之间传递对象和函数时的行为。
   - 测试 `SetAbortScriptExecution` 功能，用于在脚本执行时设置回调。

6. **对象和实例属性 (`InstanceProperties`, `GlobalObjectInstanceProperties`):**
   - 测试在函数模板的实例模板上设置属性和函数的能力。
   - 验证通过函数模板创建的对象实例是否继承了这些属性和函数。
   - 测试全局对象实例属性的处理。

7. **获取对象自身属性名 (`ObjectGetOwnPropertyNames`):**
   - 测试 `Object::GetOwnPropertyNames` 方法，用于获取对象自身的可枚举和不可枚举属性的名称。
   - 验证不同属性过滤条件下的结果。

8. **调用已知全局接收器 (`CallKnownGlobalReceiver`):**
   -  测试在特定场景下（例如，在参数求值过程中发生反优化），调用已知全局接收者的行为。

9. **影子对象和属性拦截 (`ShadowObject`):**
    - 测试使用命名和索引属性拦截器来控制属性访问。

**与 Javascript 的关系及举例说明:**

这些测试直接关联到 JavaScript 的核心功能。以下是一些与 JavaScript 功能相关的示例：

**1. UTF-16 字符串处理:**

```javascript
// JavaScript 中创建包含代理对的字符串
const str = '\uD801\uDC07';
console.log(str.length); // 输出 2
console.log(str.charCodeAt(0)); // 输出 55305 (0xD801)
console.log(str.charCodeAt(1)); // 输出 56327 (0xDC07)
```
C++ 代码中的 `Utf16Symbol` 测试就验证了 V8 引擎在 C++ 层面对这种 JavaScript 字符串的内部表示和操作是否正确。

**2. 数组索引转换:**

```javascript
const arr = [];
arr["42"] = "hello"; // JavaScript 允许字符串形式的数字作为数组索引
arr[42] = "world";

console.log(arr["42"]); // 输出 "hello"
console.log(arr[42]);  // 输出 "world"
```
`ToArrayIndex` 测试确保 V8 C++ API 能正确将 JavaScript 中的字符串 "42" 转换为数字 42 作为数组索引。

**3. 异常处理:**

```javascript
try {
  throw new RangeError("超出范围");
} catch (e) {
  console.error(e.name);    // 输出 "RangeError"
  console.error(e.message); // 输出 "超出范围"
}
```
`ErrorConstruction` 测试验证了 V8 的 C++ API 能否创建与 JavaScript 中 `new RangeError()` 等价的对象。

**4. 属性访问控制和安全:**

```javascript
// 假设有两个 iframe 或 window，代表不同的安全上下文
const iframe1 = document.createElement('iframe');
document.body.appendChild(iframe1);
const win1 = iframe1.contentWindow;
win1.globalVar = "secret";

const iframe2 = document.createElement('iframe');
document.body.appendChild(iframe2);
const win2 = iframe2.contentWindow;

// 在 win2 中尝试访问 win1 的变量，可能会受到安全限制
try {
  console.log(win1.globalVar); // 如果跨域策略允许，则可以访问
} catch (e) {
  console.error("无法访问: ", e);
}
```
`SecurityHandler` 和 `SecurityChecks` 等测试模拟了这种跨安全上下文的访问，验证 V8 是否按照安全策略正确阻止或允许访问。

**5. 上下文管理:**

虽然 JavaScript 本身不直接暴露上下文管理的 API，但 V8 的上下文概念在某些高级场景下很重要，例如使用 Node.js 的 `vm` 模块创建独立的执行沙箱。C++ 代码中的测试验证了 V8 引擎在 C++ 层的上下文创建和管理机制。

**总结:**

总而言之，文件 `v8/test/cctest/test-api.cc` 的第 6 部分专注于测试 V8 JavaScript 引擎 C++ API 的关键功能，这些功能直接支撑着 JavaScript 语言的语义和行为，包括字符串处理、异常处理、安全模型、上下文管理以及对象属性访问等方面。这些测试确保了 V8 引擎在 C++ 层面实现的正确性和可靠性。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第6部分，共18部分，请归纳一下它的功能

"""
[5] -= 2;"  // Here the surrogate pairs match up.
      "var a2 = [];"
      "var b2 = [];"
      "var c2 = [];"
      "var a2lens = [];"
      "for (var m = 0; m < 9; m++) {"
      "  for (var n = 0; n < 9; n++) {"
      "    a2.push(a[m] + a[n]);"
      "    b2.push(b[m] + b[n]);"
      "    var newc = 'x' + c[m] + c[n] + 'y';"
      "    c2.push(newc.substring(1, newc.length - 1));"
      "    var utf = alens[m] + alens[n];"  // And here.
                                            // The 'n's that start with 0xDC..
                                            // are 6-8 The 'm's that end with
                                            // 0xD8.. are 1, 4 and 7
      "    if ((m % 3) == 1 && n >= 6) utf -= 2;"
      "    a2lens.push(utf);"
      "  }"
      "}");
  Utf16Helper(context, "a", "alens", 9);
  Utf16Helper(context, "a2", "a2lens", 81);
}


static bool SameSymbol(Local<String> s1, Local<String> s2) {
  i::DirectHandle<i::String> is1 = v8::Utils::OpenDirectHandle(*s1);
  i::DirectHandle<i::String> is2 = v8::Utils::OpenDirectHandle(*s2);
  return *is1 == *is2;
}


THREADED_TEST(Utf16Symbol) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  Local<String> symbol1 = v8::String::NewFromUtf8Literal(
      context->GetIsolate(), "abc", v8::NewStringType::kInternalized);
  Local<String> symbol2 = v8::String::NewFromUtf8Literal(
      context->GetIsolate(), "abc", v8::NewStringType::kInternalized);
  CHECK(SameSymbol(symbol1, symbol2));

  CompileRun(
      "var sym0 = 'benedictus';"
      "var sym0b = 'S\xC3\xB8ren';"
      "var sym1 = '\xED\xA0\x81\xED\xB0\x87';"
      "var sym2 = '\xF0\x90\x90\x88';"
      "var sym3 = 'x\xED\xA0\x81\xED\xB0\x87';"
      "var sym4 = 'x\xF0\x90\x90\x88';"
      "if (sym1.length != 2) throw sym1;"
      "if (sym1.charCodeAt(1) != 0xDC07) throw sym1.charCodeAt(1);"
      "if (sym2.length != 2) throw sym2;"
      "if (sym2.charCodeAt(1) != 0xDC08) throw sym2.charCodeAt(2);"
      "if (sym3.length != 3) throw sym3;"
      "if (sym3.charCodeAt(2) != 0xDC07) throw sym1.charCodeAt(2);"
      "if (sym4.length != 3) throw sym4;"
      "if (sym4.charCodeAt(2) != 0xDC08) throw sym2.charCodeAt(2);");
  Local<String> sym0 = v8::String::NewFromUtf8Literal(
      context->GetIsolate(), "benedictus", v8::NewStringType::kInternalized);
  Local<String> sym0b = v8::String::NewFromUtf8Literal(
      context->GetIsolate(), "S\xC3\xB8ren", v8::NewStringType::kInternalized);
  Local<String> sym1 = v8::String::NewFromUtf8Literal(
      context->GetIsolate(), "\xED\xA0\x81\xED\xB0\x87",
      v8::NewStringType::kInternalized);
  Local<String> sym2 =
      v8::String::NewFromUtf8Literal(context->GetIsolate(), "\xF0\x90\x90\x88",
                                     v8::NewStringType::kInternalized);
  Local<String> sym3 = v8::String::NewFromUtf8Literal(
      context->GetIsolate(), "x\xED\xA0\x81\xED\xB0\x87",
      v8::NewStringType::kInternalized);
  Local<String> sym4 =
      v8::String::NewFromUtf8Literal(context->GetIsolate(), "x\xF0\x90\x90\x88",
                                     v8::NewStringType::kInternalized);
  v8::Local<v8::Object> global = context->Global();
  Local<Value> s0 =
      global->Get(context.local(), v8_str("sym0")).ToLocalChecked();
  Local<Value> s0b =
      global->Get(context.local(), v8_str("sym0b")).ToLocalChecked();
  Local<Value> s1 =
      global->Get(context.local(), v8_str("sym1")).ToLocalChecked();
  Local<Value> s2 =
      global->Get(context.local(), v8_str("sym2")).ToLocalChecked();
  Local<Value> s3 =
      global->Get(context.local(), v8_str("sym3")).ToLocalChecked();
  Local<Value> s4 =
      global->Get(context.local(), v8_str("sym4")).ToLocalChecked();
  CHECK(SameSymbol(sym0, Local<String>::Cast(s0)));
  CHECK(SameSymbol(sym0b, Local<String>::Cast(s0b)));
  CHECK(SameSymbol(sym1, Local<String>::Cast(s1)));
  CHECK(SameSymbol(sym2, Local<String>::Cast(s2)));
  CHECK(SameSymbol(sym3, Local<String>::Cast(s3)));
  CHECK(SameSymbol(sym4, Local<String>::Cast(s4)));
}


THREADED_TEST(Utf16MissingTrailing) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  // Make sure it will go past the buffer, so it will call `WriteUtf16Slow`
  int size = 1024 * 64;
  uint8_t* buffer = new uint8_t[size];
  for (int i = 0; i < size; i += 4) {
    buffer[i] = 0xF0;
    buffer[i + 1] = 0x9D;
    buffer[i + 2] = 0x80;
    buffer[i + 3] = 0x9E;
  }

  // Now invoke the decoder without last 3 bytes
  v8::Local<v8::String> str =
      v8::String::NewFromUtf8(
          context->GetIsolate(), reinterpret_cast<char*>(buffer),
          v8::NewStringType::kNormal, size - 3).ToLocalChecked();
  USE(str);
  delete[] buffer;
}

START_ALLOW_USE_DEPRECATED()

THREADED_TEST(Utf16Trailing3Byte_Value) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  // Make sure it will go past the buffer, so it will call `WriteUtf16Slow`
  int size = 1024 * 63;
  uint8_t* buffer = new uint8_t[size];
  for (int i = 0; i < size; i += 3) {
    buffer[i] = 0xE2;
    buffer[i + 1] = 0x80;
    buffer[i + 2] = 0xA6;
  }

  // Now invoke the decoder without last 3 bytes
  v8::Local<v8::String> str =
      v8::String::NewFromUtf8(isolate, reinterpret_cast<char*>(buffer),
                              v8::NewStringType::kNormal, size)
          .ToLocalChecked();

  v8::String::Value value(isolate, str);
  CHECK_EQ(value.length(), size / 3);
  CHECK_EQ((*value)[value.length() - 1], 0x2026);

  delete[] buffer;
}

END_ALLOW_USE_DEPRECATED()

THREADED_TEST(Utf16Trailing3Byte_ValueView) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  // Make sure it will go past the buffer, so it will call `WriteUtf16Slow`
  int size = 1024 * 63;
  uint8_t* buffer = new uint8_t[size];
  for (int i = 0; i < size; i += 3) {
    buffer[i] = 0xE2;
    buffer[i + 1] = 0x80;
    buffer[i + 2] = 0xA6;
  }

  // Now invoke the decoder without last 3 bytes
  v8::Local<v8::String> str =
      v8::String::NewFromUtf8(isolate, reinterpret_cast<char*>(buffer),
                              v8::NewStringType::kNormal, size)
          .ToLocalChecked();

  v8::String::ValueView value(isolate, str);
  CHECK(!value.is_one_byte());
  CHECK_EQ(value.length(), size / 3);
  CHECK_EQ(value.data16()[value.length() - 1], 0x2026);

  delete[] buffer;
}

THREADED_TEST(ToArrayIndex) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<String> str = v8_str("42");
  v8::MaybeLocal<v8::Uint32> index = str->ToArrayIndex(context.local());
  CHECK(!index.IsEmpty());
  CHECK_EQ(42.0,
           index.ToLocalChecked()->Uint32Value(context.local()).FromJust());
  str = v8_str("42asdf");
  index = str->ToArrayIndex(context.local());
  CHECK(index.IsEmpty());
  str = v8_str("-42");
  index = str->ToArrayIndex(context.local());
  CHECK(index.IsEmpty());
  str = v8_str("4294967294");
  index = str->ToArrayIndex(context.local());
  CHECK(!index.IsEmpty());
  CHECK_EQ(4294967294.0,
           index.ToLocalChecked()->Uint32Value(context.local()).FromJust());
  v8::Local<v8::Number> num = v8::Number::New(isolate, 1);
  index = num->ToArrayIndex(context.local());
  CHECK(!index.IsEmpty());
  CHECK_EQ(1.0,
           index.ToLocalChecked()->Uint32Value(context.local()).FromJust());
  num = v8::Number::New(isolate, -1);
  index = num->ToArrayIndex(context.local());
  CHECK(index.IsEmpty());
  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  index = obj->ToArrayIndex(context.local());
  CHECK(index.IsEmpty());
}

THREADED_TEST(ErrorConstruction) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  v8::Local<String> foo = v8_str("foo");
  v8::Local<String> message = v8_str("message");
  v8::Local<Value> range_error = v8::Exception::RangeError(foo);
  CHECK(range_error->IsObject());
  CHECK(range_error.As<v8::Object>()
            ->Get(context.local(), message)
            .ToLocalChecked()
            ->Equals(context.local(), foo)
            .FromJust());
  v8::Local<Value> reference_error = v8::Exception::ReferenceError(foo);
  CHECK(reference_error->IsObject());
  CHECK(reference_error.As<v8::Object>()
            ->Get(context.local(), message)
            .ToLocalChecked()
            ->Equals(context.local(), foo)
            .FromJust());
  v8::Local<Value> syntax_error = v8::Exception::SyntaxError(foo);
  CHECK(syntax_error->IsObject());
  CHECK(syntax_error.As<v8::Object>()
            ->Get(context.local(), message)
            .ToLocalChecked()
            ->Equals(context.local(), foo)
            .FromJust());
  v8::Local<Value> type_error = v8::Exception::TypeError(foo);
  CHECK(type_error->IsObject());
  CHECK(type_error.As<v8::Object>()
            ->Get(context.local(), message)
            .ToLocalChecked()
            ->Equals(context.local(), foo)
            .FromJust());
  v8::Local<Value> error = v8::Exception::Error(foo);
  CHECK(error->IsObject());
  CHECK(error.As<v8::Object>()
            ->Get(context.local(), message)
            .ToLocalChecked()
            ->Equals(context.local(), foo)
            .FromJust());
}

THREADED_TEST(ExceptionCreateMessageLength) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  // Test that the message is not truncated.
  TryCatch try_catch(context->GetIsolate());
  CompileRun(
      "var message = 'm';"
      "while (message.length < 1000) message += message;"
      "throw message;");
  CHECK(try_catch.HasCaught());

  CHECK_LT(1000, try_catch.Message()->Get()->Length());
}

static void YGetter(Local<Name> name,
                    const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(10));
}

static void YSetter(Local<Name> name, Local<Value> value,
                    const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  Local<Object> this_obj = info.This().As<Object>();
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  if (this_obj->Has(context, name).FromJust())
    this_obj->Delete(context, name).FromJust();
  CHECK(this_obj->Set(context, name, value).FromJust());
}

THREADED_TEST(DeleteAccessor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("y"), YGetter, YSetter);
  LocalContext context;
  v8::Local<v8::Object> holder =
      obj->NewInstance(context.local()).ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("holder"), holder)
            .FromJust());
  v8::Local<Value> result =
      CompileRun("holder.y = 11; holder.y = 12; holder.y");
  CHECK_EQ(12u, result->Uint32Value(context.local()).FromJust());
}


static int trouble_nesting = 0;
static void TroubleCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  trouble_nesting++;

  // Call a JS function that throws an uncaught exception.
  Local<v8::Context> context = args.GetIsolate()->GetCurrentContext();
  Local<v8::Object> arg_this = context->Global();
  Local<Value> trouble_callee =
      (trouble_nesting == 3)
          ? arg_this->Get(context, v8_str("trouble_callee")).ToLocalChecked()
          : arg_this->Get(context, v8_str("trouble_caller")).ToLocalChecked();
  CHECK(trouble_callee->IsFunction());
  args.GetReturnValue().Set(Function::Cast(*trouble_callee)
                                ->Call(context, arg_this, 0, nullptr)
                                .FromMaybe(v8::Local<v8::Value>()));
}


static int report_count = 0;
static void ApiUncaughtExceptionTestListener(v8::Local<v8::Message>,
                                             v8::Local<Value>) {
  report_count++;
}


// Counts uncaught exceptions, but other tests running in parallel
// also have uncaught exceptions.
TEST(ApiUncaughtException) {
  report_count = 0;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  isolate->AddMessageListener(ApiUncaughtExceptionTestListener);

  Local<v8::FunctionTemplate> fun =
      v8::FunctionTemplate::New(isolate, TroubleCallback);
  v8::Local<v8::Object> global = env->Global();
  CHECK(global->Set(env.local(), v8_str("trouble"),
                    fun->GetFunction(env.local()).ToLocalChecked())
            .FromJust());

  CompileRun(
      "function trouble_callee() {"
      "  var x = null;"
      "  return x.foo;"
      "};"
      "function trouble_caller() {"
      "  trouble();"
      "};");
  Local<Value> trouble =
      global->Get(env.local(), v8_str("trouble")).ToLocalChecked();
  CHECK(trouble->IsFunction());
  Local<Value> trouble_callee =
      global->Get(env.local(), v8_str("trouble_callee")).ToLocalChecked();
  CHECK(trouble_callee->IsFunction());
  Local<Value> trouble_caller =
      global->Get(env.local(), v8_str("trouble_caller")).ToLocalChecked();
  CHECK(trouble_caller->IsFunction());
  Function::Cast(*trouble_caller)
      ->Call(env.local(), global, 0, nullptr)
      .FromMaybe(v8::Local<v8::Value>());
  CHECK_EQ(1, report_count);
  isolate->RemoveMessageListeners(ApiUncaughtExceptionTestListener);
}


static const char* script_resource_name = "ExceptionInNativeScript.js";
static void ExceptionInNativeScriptTestListener(v8::Local<v8::Message> message,
                                                v8::Local<Value>) {
  v8::Isolate* isolate = message->GetIsolate();
  v8::Local<v8::Value> name_val = message->GetScriptOrigin().ResourceName();
  CHECK(!name_val.IsEmpty() && name_val->IsString());
  v8::String::Utf8Value name(isolate,
                             message->GetScriptOrigin().ResourceName());
  CHECK_EQ(0, strcmp(script_resource_name, *name));
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  CHECK_EQ(3, message->GetLineNumber(context).FromJust());
  v8::String::Utf8Value source_line(
      isolate, message->GetSourceLine(context).ToLocalChecked());
  CHECK_EQ(0, strcmp("  new o.foo();", *source_line));
}


TEST(ExceptionInNativeScript) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  isolate->AddMessageListener(ExceptionInNativeScriptTestListener);

  Local<v8::FunctionTemplate> fun =
      v8::FunctionTemplate::New(isolate, TroubleCallback);
  v8::Local<v8::Object> global = env->Global();
  CHECK(global->Set(env.local(), v8_str("trouble"),
                    fun->GetFunction(env.local()).ToLocalChecked())
            .FromJust());

  CompileRunWithOrigin(
      "function trouble() {\n"
      "  var o = {};\n"
      "  new o.foo();\n"
      "};",
      script_resource_name);
  Local<Value> trouble =
      global->Get(env.local(), v8_str("trouble")).ToLocalChecked();
  CHECK(trouble->IsFunction());
  CHECK(Function::Cast(*trouble)
            ->Call(env.local(), global, 0, nullptr)
            .IsEmpty());
  isolate->RemoveMessageListeners(ExceptionInNativeScriptTestListener);
}


TEST(CompilationErrorUsingTryCatchHandler) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::TryCatch try_catch(env->GetIsolate());
  CHECK(v8_try_compile("This doesn't &*&@#$&*^ compile.").IsEmpty());
  CHECK(*try_catch.Exception());
  CHECK(try_catch.HasCaught());
}

// For use within the TestSecurityHandler() test.
static bool g_security_callback_result = false;
static bool SecurityTestCallback(Local<v8::Context> accessing_context,
                                 Local<v8::Object> accessed_object,
                                 Local<v8::Value> data) {
  printf("a\n");
  CHECK(!data.IsEmpty() && data->IsInt32());
  CHECK_EQ(42, data->Int32Value(accessing_context).FromJust());
  return g_security_callback_result;
}


// SecurityHandler can't be run twice
TEST(SecurityHandler) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope0(isolate);
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  global_template->SetAccessCheckCallback(SecurityTestCallback, v8_num(42));
  // Create an environment
  v8::Local<Context> context0 = Context::New(isolate, nullptr, global_template);
  context0->Enter();

  v8::Local<v8::Object> global0 = context0->Global();
  v8::Local<Script> script0 = v8_compile("foo = 111");
  script0->Run(context0).ToLocalChecked();
  CHECK(global0->Set(context0, v8_str("0"), v8_num(999)).FromJust());
  v8::Local<Value> foo0 =
      global0->Get(context0, v8_str("foo")).ToLocalChecked();
  CHECK_EQ(111, foo0->Int32Value(context0).FromJust());
  v8::Local<Value> z0 = global0->Get(context0, v8_str("0")).ToLocalChecked();
  CHECK_EQ(999, z0->Int32Value(context0).FromJust());

  // Create another environment, should fail security checks.
  v8::HandleScope scope1(isolate);

  v8::Local<Context> context1 = Context::New(isolate, nullptr, global_template);
  context1->Enter();

  v8::Local<v8::Object> global1 = context1->Global();
  global1->Set(context1, v8_str("othercontext"), global0).FromJust();
  // This set will fail the security check.
  v8::Local<Script> script1 =
      v8_compile("othercontext.foo = 222; othercontext[0] = 888;");
  CHECK(script1->Run(context1).IsEmpty());
  g_security_callback_result = true;
  // This read will pass the security check.
  v8::Local<Value> foo1 =
      global0->Get(context1, v8_str("foo")).ToLocalChecked();
  CHECK_EQ(111, foo1->Int32Value(context0).FromJust());
  // This read will pass the security check.
  v8::Local<Value> z1 = global0->Get(context1, v8_str("0")).ToLocalChecked();
  CHECK_EQ(999, z1->Int32Value(context1).FromJust());

  // Create another environment, should pass security checks.
  {
    v8::HandleScope scope2(isolate);
    LocalContext context2;
    v8::Local<v8::Object> global2 = context2->Global();
    CHECK(global2->Set(context2.local(), v8_str("othercontext"), global0)
              .FromJust());
    v8::Local<Script> script2 =
        v8_compile("othercontext.foo = 333; othercontext[0] = 888;");
    script2->Run(context2.local()).ToLocalChecked();
    v8::Local<Value> foo2 =
        global0->Get(context2.local(), v8_str("foo")).ToLocalChecked();
    CHECK_EQ(333, foo2->Int32Value(context2.local()).FromJust());
    v8::Local<Value> z2 =
        global0->Get(context2.local(), v8_str("0")).ToLocalChecked();
    CHECK_EQ(888, z2->Int32Value(context2.local()).FromJust());
  }

  context1->Exit();
  context0->Exit();
}


THREADED_TEST(SecurityChecks) {
  LocalContext env1;
  v8::HandleScope handle_scope(env1->GetIsolate());
  v8::Local<Context> env2 = Context::New(env1->GetIsolate());

  Local<Value> foo = v8_str("foo");
  Local<Value> bar = v8_str("bar");

  // Set to the same domain.
  env1->SetSecurityToken(foo);

  // Create a function in env1.
  CompileRun("spy=function(){return spy;}");
  Local<Value> spy =
      env1->Global()->Get(env1.local(), v8_str("spy")).ToLocalChecked();
  CHECK(spy->IsFunction());

  // Create another function accessing global objects.
  CompileRun("spy2=function(){return new this.Array();}");
  Local<Value> spy2 =
      env1->Global()->Get(env1.local(), v8_str("spy2")).ToLocalChecked();
  CHECK(spy2->IsFunction());

  // Switch to env2 in the same domain and invoke spy on env2.
  {
    env2->SetSecurityToken(foo);
    // Enter env2
    Context::Scope scope_env2(env2);
    Local<Value> result = Function::Cast(*spy)
                              ->Call(env2, env2->Global(), 0, nullptr)
                              .ToLocalChecked();
    CHECK(result->IsFunction());
  }

  {
    env2->SetSecurityToken(bar);
    Context::Scope scope_env2(env2);

    // Call cross_domain_call, it should throw an exception
    v8::TryCatch try_catch(env1->GetIsolate());
    CHECK(Function::Cast(*spy2)
              ->Call(env2, env2->Global(), 0, nullptr)
              .IsEmpty());
    CHECK(try_catch.HasCaught());
  }
}


// Regression test case for issue 1183439.
THREADED_TEST(SecurityChecksForPrototypeChain) {
  LocalContext current;
  v8::HandleScope scope(current->GetIsolate());
  v8::Local<Context> other = Context::New(current->GetIsolate());

  // Change context to be able to get to the Object function in the
  // other context without hitting the security checks.
  v8::Local<Value> other_object;
  {
    Context::Scope context_scope(other);
    other_object =
        other->Global()->Get(other, v8_str("Object")).ToLocalChecked();
    CHECK(other->Global()->Set(other, v8_num(42), v8_num(87)).FromJust());
  }

  CHECK(current->Global()
            ->Set(current.local(), v8_str("other"), other->Global())
            .FromJust());
  CHECK(v8_compile("other")
            ->Run(current.local())
            .ToLocalChecked()
            ->Equals(current.local(), other->Global())
            .FromJust());

  // Make sure the security check fails here and we get an undefined
  // result instead of getting the Object function. Repeat in a loop
  // to make sure to exercise the IC code.
  v8::Local<Script> access_other0 = v8_compile("other.Object");
  v8::Local<Script> access_other1 = v8_compile("other[42]");
  for (int i = 0; i < 5; i++) {
    CHECK(access_other0->Run(current.local()).IsEmpty());
    CHECK(access_other1->Run(current.local()).IsEmpty());
  }

  // Create an object that has 'other' in its prototype chain and make
  // sure we cannot access the Object function indirectly through
  // that. Repeat in a loop to make sure to exercise the IC code.
  v8_compile(
      "function F() { };"
      "F.prototype = other;"
      "var f = new F();")
      ->Run(current.local())
      .ToLocalChecked();
  v8::Local<Script> access_f0 = v8_compile("f.Object");
  v8::Local<Script> access_f1 = v8_compile("f[42]");
  for (int j = 0; j < 5; j++) {
    CHECK(access_f0->Run(current.local()).IsEmpty());
    CHECK(access_f1->Run(current.local()).IsEmpty());
  }

  // Now it gets hairy: Set the prototype for the other global object
  // to be the current global object. The prototype chain for 'f' now
  // goes through 'other' but ends up in the current global object.
  {
    Context::Scope context_scope(other);
    CHECK(other->Global()
              ->Set(other, v8_str("__proto__"), current->Global())
              .FromJust());
  }
  // Set a named and an index property on the current global
  // object. To force the lookup to go through the other global object,
  // the properties must not exist in the other global object.
  CHECK(current->Global()
            ->Set(current.local(), v8_str("foo"), v8_num(100))
            .FromJust());
  CHECK(current->Global()
            ->Set(current.local(), v8_num(99), v8_num(101))
            .FromJust());
  // Try to read the properties from f and make sure that the access
  // gets stopped by the security checks on the other global object.
  Local<Script> access_f2 = v8_compile("f.foo");
  Local<Script> access_f3 = v8_compile("f[99]");
  for (int k = 0; k < 5; k++) {
    CHECK(access_f2->Run(current.local()).IsEmpty());
    CHECK(access_f3->Run(current.local()).IsEmpty());
  }
}


static bool security_check_with_gc_called;

static bool SecurityTestCallbackWithGC(Local<v8::Context> accessing_context,
                                       Local<v8::Object> accessed_object,
                                       Local<v8::Value> data) {
  i::heap::InvokeMajorGC(CcTest::heap());
  security_check_with_gc_called = true;
  return true;
}


TEST(SecurityTestGCAllowed) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  object_template->SetAccessCheckCallback(SecurityTestCallbackWithGC);

  v8::Local<Context> context = Context::New(isolate);
  v8::Context::Scope context_scope(context);

  CHECK(context->Global()
            ->Set(context, v8_str("obj"),
                  object_template->NewInstance(context).ToLocalChecked())
            .FromJust());

  security_check_with_gc_called = false;
  CompileRun("obj[0] = new String(1002);");
  CHECK(security_check_with_gc_called);

  security_check_with_gc_called = false;
  CHECK(CompileRun("obj[0]")
            ->ToString(context)
            .ToLocalChecked()
            ->Equals(context, v8_str("1002"))
            .FromJust());
  CHECK(security_check_with_gc_called);
}


THREADED_TEST(CrossDomainDelete) {
  LocalContext env1;
  v8::HandleScope handle_scope(env1->GetIsolate());
  v8::Local<Context> env2 = Context::New(env1->GetIsolate());

  Local<Value> foo = v8_str("foo");
  Local<Value> bar = v8_str("bar");

  // Set to the same domain.
  env1->SetSecurityToken(foo);
  env2->SetSecurityToken(foo);

  CHECK(
      env1->Global()->Set(env1.local(), v8_str("prop"), v8_num(3)).FromJust());
  CHECK(env2->Global()->Set(env2, v8_str("env1"), env1->Global()).FromJust());

  // Change env2 to a different domain and delete env1.prop.
  env2->SetSecurityToken(bar);
  {
    Context::Scope scope_env2(env2);
    Local<Value> result =
        CompileRun("delete env1.prop");
    CHECK(result.IsEmpty());
  }

  // Check that env1.prop still exists.
  Local<Value> v =
      env1->Global()->Get(env1.local(), v8_str("prop")).ToLocalChecked();
  CHECK(v->IsNumber());
  CHECK_EQ(3, v->Int32Value(env1.local()).FromJust());
}


THREADED_TEST(CrossDomainPropertyIsEnumerable) {
  LocalContext env1;
  v8::HandleScope handle_scope(env1->GetIsolate());
  v8::Local<Context> env2 = Context::New(env1->GetIsolate());

  Local<Value> foo = v8_str("foo");
  Local<Value> bar = v8_str("bar");

  // Set to the same domain.
  env1->SetSecurityToken(foo);
  env2->SetSecurityToken(foo);

  CHECK(
      env1->Global()->Set(env1.local(), v8_str("prop"), v8_num(3)).FromJust());
  CHECK(env2->Global()->Set(env2, v8_str("env1"), env1->Global()).FromJust());

  // env1.prop is enumerable in env2.
  Local<String> test = v8_str("propertyIsEnumerable.call(env1, 'prop')");
  {
    Context::Scope scope_env2(env2);
    Local<Value> result = CompileRun(test);
    CHECK(result->IsTrue());
  }

  // Change env2 to a different domain and test again.
  env2->SetSecurityToken(bar);
  {
    Context::Scope scope_env2(env2);
    Local<Value> result = CompileRun(test);
    CHECK(result.IsEmpty());
  }
}


THREADED_TEST(CrossDomainFor) {
  LocalContext env1;
  v8::HandleScope handle_scope(env1->GetIsolate());
  v8::Local<Context> env2 = Context::New(env1->GetIsolate());

  Local<Value> foo = v8_str("foo");
  Local<Value> bar = v8_str("bar");

  // Set to the same domain.
  env1->SetSecurityToken(foo);
  env2->SetSecurityToken(foo);

  CHECK(
      env1->Global()->Set(env1.local(), v8_str("prop"), v8_num(3)).FromJust());
  CHECK(env2->Global()->Set(env2, v8_str("env1"), env1->Global()).FromJust());

  // Change env2 to a different domain and set env1's global object
  // as the __proto__ of an object in env2 and enumerate properties
  // in for-in. It shouldn't enumerate properties on env1's global
  // object. It shouldn't throw either, just silently ignore them.
  env2->SetSecurityToken(bar);
  {
    Context::Scope scope_env2(env2);
    Local<Value> result = CompileRun(
        "(function() {"
        "  try {"
        "    for (var p in env1) {"
        "      if (p == 'prop') return false;"
        "    }"
        "    return true;"
        "  } catch (e) {"
        "    return false;"
        "  }"
        "})()");
    CHECK(result->IsTrue());
  }
}


THREADED_TEST(CrossDomainForInOnPrototype) {
  LocalContext env1;
  v8::HandleScope handle_scope(env1->GetIsolate());
  v8::Local<Context> env2 = Context::New(env1->GetIsolate());

  Local<Value> foo = v8_str("foo");
  Local<Value> bar = v8_str("bar");

  // Set to the same domain.
  env1->SetSecurityToken(foo);
  env2->SetSecurityToken(foo);

  CHECK(
      env1->Global()->Set(env1.local(), v8_str("prop"), v8_num(3)).FromJust());
  CHECK(env2->Global()->Set(env2, v8_str("env1"), env1->Global()).FromJust());

  // Change env2 to a different domain and set env1's global object
  // as the __proto__ of an object in env2 and enumerate properties
  // in for-in. It shouldn't enumerate properties on env1's global
  // object.
  env2->SetSecurityToken(bar);
  {
    Context::Scope scope_env2(env2);
    Local<Value> result = CompileRun(
        "(function() {"
        "  var obj = { '__proto__': env1 };"
        "  try {"
        "    for (var p in obj) {"
        "      if (p == 'prop') return false;"
        "    }"
        "    return true;"
        "  } catch (e) {"
        "    return false;"
        "  }"
        "})()");
    CHECK(result->IsTrue());
  }
}


TEST(ContextDetachGlobal) {
  LocalContext env1;
  v8::HandleScope handle_scope(env1->GetIsolate());
  v8::Local<Context> env2 = Context::New(env1->GetIsolate());


  Local<Value> foo = v8_str("foo");

  // Set to the same domain.
  env1->SetSecurityToken(foo);
  env2->SetSecurityToken(foo);

  // Enter env2
  env2->Enter();

  // Create a function in env2 and add a reference to it in env1.
  Local<v8::Object> global2 = env2->Global();
  CHECK(global2->Set(env2, v8_str("prop"),
                     v8::Integer::New(env2->GetIsolate(), 1))
            .FromJust());
  CompileRun("function getProp() {return prop;}");

  CHECK(env1->Global()
            ->Set(env1.local(), v8_str("getProp"),
                  global2->Get(env2, v8_str("getProp")).ToLocalChecked())
            .FromJust());

  // Detach env2's global, and reuse the global object of env2
  env2->Exit();
  env2->DetachGlobal();

  v8::Local<Context> env3 = Context::New(
      env1->GetIsolate(), nullptr, v8::Local<v8::ObjectTemplate>(), global2);
  env3->SetSecurityToken(v8_str("bar"));

  env3->Enter();
  Local<v8::Object> global3 = env3->Global();
  CHECK(global2->Equals(env3, global3).FromJust());
  CHECK(global3->Get(env3, v8_str("prop")).ToLocalChecked()->IsUndefined());
  CHECK(global3->Get(env3, v8_str("getProp")).ToLocalChecked()->IsUndefined());
  CHECK(global3->Set(env3, v8_str("prop"),
                     v8::Integer::New(env3->GetIsolate(), -1))
            .FromJust());
  CHECK(global3->Set(env3, v8_str("prop2"),
                     v8::Integer::New(env3->GetIsolate(), 2))
            .FromJust());
  env3->Exit();

  // Call getProp in env1, and it should return the value 1
  {
    Local<v8::Object> global1 = env1->Global();
    Local<Value> get_prop =
        global1->Get(env1.local(), v8_str("getProp")).ToLocalChecked();
    CHECK(get_prop->IsFunction());
    v8::TryCatch try_catch(env1->GetIsolate());
    Local<Value> r = Function::Cast(*get_prop)
                         ->Call(env1.local(), global1, 0, nullptr)
                         .ToLocalChecked();
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(1, r->Int32Value(env1.local()).FromJust());
  }

  // Check that env3 is not accessible from env1
  {
    v8::MaybeLocal<Value> r = global3->Get(env1.local(), v8_str("prop2"));
    CHECK(r.IsEmpty());
  }
}


TEST(DetachGlobal) {
  LocalContext env1;
  v8::HandleScope scope(env1->GetIsolate());

  // Create second environment.
  v8::Local<Context> env2 = Context::New(env1->GetIsolate());

  Local<Value> foo = v8_str("foo");

  // Set same security token for env1 and env2.
  env1->SetSecurityToken(foo);
  env2->SetSecurityToken(foo);

  // Create a property on the global object in env2.
  {
    v8::Context::Scope context_scope(env2);
    CHECK(env2->Global()
              ->Set(env2, v8_str("p"), v8::Integer::New(env2->GetIsolate(), 42))
              .FromJust());
  }

  // Create a reference to env2 global from env1 global.
  CHECK(env1->Global()
            ->Set(env1.local(), v8_str("other"), env2->Global())
            .FromJust());

  // Check that we have access to other.p in env2 from env1.
  Local<Value> result = CompileRun("other.p");
  CHECK(result->IsInt32());
  CHECK_EQ(42, result->Int32Value(env1.local()).FromJust());

  // Hold on to global from env2 and detach global from env2.
  Local<v8::Object> global2 = env2->Global();
  env2->DetachGlobal();

  // Check that the global has been detached. No other.p property can
  // be found.
  result = CompileRun("other.p");
  CHECK(result.IsEmpty());

  // Reuse global2 for env3.
  v8::Local<Context> env3 = Context::New(
      env1->GetIsolate(), nullptr, v8::Local<v8::ObjectTemplate>(), global2);
  CHECK(global2->Equals(env1.local(), env3->Global()).FromJust());

  // Start by using the same security token for env3 as for env1 and env2.
  env3->SetSecurityToken(foo);

  // Create a property on the global object in env3.
  {
    v8::Context::Scope context_scope(env3);
    CHECK(env3->Global()
              ->Set(env3, v8_str("p"), v8::Integer::New(env3->GetIsolate(), 24))
              .FromJust());
  }

  // Check that other.p is now the property in env3 and that we have access.
  result = CompileRun("other.p");
  CHECK(result->IsInt32());
  CHECK_EQ(24, result->Int32Value(env3).FromJust());
}


void GetThisX(const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  info.GetReturnValue().Set(
      context->Global()->Get(context, v8_str("x")).ToLocalChecked());
}


TEST(DetachedAccesses) {
  LocalContext env1;
  v8::HandleScope scope(env1->GetIsolate());

  // Create second environment.
  Local<ObjectTemplate> inner_global_template =
      FunctionTemplate::New(env1->GetIsolate())->InstanceTemplate();
  inner_global_template ->SetAccessorProperty(
      v8_str("this_x"), FunctionTemplate::New(env1->GetIsolate(), GetThisX));
  v8::Local<Context> env2 =
      Context::New(env1->GetIsolate(), nullptr, inner_global_template);

  Local<Value> foo = v8_str("foo");

  // Set same security token for env1 and env2.
  env1->SetSecurityToken(foo);
  env2->SetSecurityToken(foo);

  CHECK(env1->Global()
            ->Set(env1.local(), v8_str("x"), v8_str("env1_x"))
            .FromJust());

  {
    v8::Context::Scope context_scope(env2);
    CHECK(env2->Global()->Set(env2, v8_str("x"), v8_str("env2_x")).FromJust());
    CompileRun(
        "function bound_x() { return x; }"
        "function get_x()   { return this.x; }"
        "function get_x_w() { return (function() {return this.x;})(); }");
    CHECK(env1->Global()
              ->Set(env1.local(), v8_str("bound_x"), CompileRun("bound_x"))
              .FromJust());
    CHECK(env1->Global()
              ->Set(env1.local(), v8_str("get_x"), CompileRun("get_x"))
              .FromJust());
    CHECK(env1->Global()
              ->Set(env1.local(), v8_str("get_x_w"), CompileRun("get_x_w"))
              .FromJust());
    env1->Global()
        ->Set(env1.local(), v8_str("this_x"),
              CompileRun("Object.getOwnPropertyDescriptor(this, 'this_x').get"))
        .FromJust();
  }

  Local<Object> env2_global = env2->Global();
  env2->DetachGlobal();

  Local<Value> result;
  result = CompileRun("bound_x()");
  CHECK(v8_str("env2_x")->Equals(env1.local(), result).FromJust());
  result = CompileRun("get_x()");
  CHECK(result.IsEmpty());
  result = CompileRun("get_x_w()");
  CHECK(result.IsEmpty());
  result = CompileRun("this_x()");
  CHECK(v8_str("env2_x")->Equals(env1.local(), result).FromJust());

  // Reattach env2's proxy
  env2 = Context::New(env1->GetIsolate(), nullptr,
                      v8::Local<v8::ObjectTemplate>(), env2_global);
  env2->SetSecurityToken(foo);
  {
    v8::Context::Scope context_scope(env2);
    CHECK(env2->Global()->Set(env2, v8_str("x"), v8_str("env3_x")).FromJust());
    CHECK(env2->Global()->Set(env2, v8_str("env1"), env1->Global()).FromJust());
    result = CompileRun(
        "results = [];"
        "for (var i = 0; i < 4; i++ ) {"
        "  results.push(env1.bound_x());"
        "  results.push(env1.get_x());"
        "  results.push(env1.get_x_w());"
        "  results.push(env1.this_x());"
        "}"
        "results");
    Local<v8::Array> results = Local<v8::Array>::Cast(result);
    CHECK_EQ(16u, results->Length());
    for (int i = 0; i < 16; i += 4) {
      CHECK(v8_str("env2_x")
                ->Equals(env2, results->Get(env2, i + 0).ToLocalChecked())
                .FromJust());
      CHECK(v8_str("env1_x")
                ->Equals(env2, results->Get(env2, i + 1).ToLocalChecked())
                .FromJust());
      CHECK(v8_str("env3_x")
                ->Equals(env2, results->Get(env2, i + 2).ToLocalChecked())
                .FromJust());
      CHECK(v8_str("env2_x")
                ->Equals(env2, results->Get(env2, i + 3).ToLocalChecked())
                .FromJust());
    }
  }

  result = CompileRun(
      "results = [];"
      "for (var i = 0; i < 4; i++ ) {"
      "  results.push(bound_x());"
      "  results.push(get_x());"
      "  results.push(get_x_w());"
      "  results.push(this_x());"
      "}"
      "results");
  Local<v8::Array> results = Local<v8::Array>::Cast(result);
  CHECK_EQ(16u, results->Length());
  for (int i = 0; i < 16; i += 4) {
    CHECK(v8_str("env2_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 0).ToLocalChecked())
              .FromJust());
    CHECK(v8_str("env3_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 1).ToLocalChecked())
              .FromJust());
    CHECK(v8_str("env3_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 2).ToLocalChecked())
              .FromJust());
    CHECK(v8_str("env2_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 3).ToLocalChecked())
              .FromJust());
  }

  result = CompileRun(
      "results = [];"
      "for (var i = 0; i < 4; i++ ) {"
      "  results.push(this.bound_x());"
      "  results.push(this.get_x());"
      "  results.push(this.get_x_w());"
      "  results.push(this.this_x());"
      "}"
      "results");
  results = Local<v8::Array>::Cast(result);
  CHECK_EQ(16u, results->Length());
  for (int i = 0; i < 16; i += 4) {
    CHECK(v8_str("env2_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 0).ToLocalChecked())
              .FromJust());
    CHECK(v8_str("env1_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 1).ToLocalChecked())
              .FromJust());
    CHECK(v8_str("env3_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 2).ToLocalChecked())
              .FromJust());
    CHECK(v8_str("env2_x")
              ->Equals(env1.local(),
                       results->Get(env1.local(), i + 3).ToLocalChecked())
              .FromJust());
  }
}


static bool allowed_access = false;
static bool AccessBlocker(Local<v8::Context> accessing_context,
                          Local<v8::Object> accessed_object,
                          Local<v8::Value> data) {
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  return context->Global()->Equals(context, accessed_object).FromJust() ||
         allowed_access;
}

static void UnreachableGetter(Local<Name> name,
                              const v8::PropertyCallbackInfo<v8::Value>& info) {
  UNREACHABLE();  // This function should not be called..
}

static void UnreachableSetter(Local<Name>, Local<Value>,
                              const v8::PropertyCallbackInfo<void>&) {
  UNREACHABLE();  // This function should not be called.
}

static void UnreachableFunction(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  UNREACHABLE();  // This function should not be called..
}


TEST(AccessControl) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);

  global_template->SetAccessCheckCallback(AccessBlocker);

  // Add an accessor that is not accessible by cross-domain JS code.
  global_template->SetNativeDataProperty(v8_str("blocked_prop"),
                                         UnreachableGetter, UnreachableSetter,
                                         v8::Local<Value>());

  global_template->SetAccessorProperty(
      v8_str("blocked_js_prop"),
      v8::FunctionTemplate::New(isolate, UnreachableFunction),
      v8::FunctionTemplate::New(isolate, UnreachableFunction), v8::None);

  // Create an environment
  v8::Local<Context> context0 = Context::New(isolate, nullptr, global_template);
  context0->Enter();

  v8::Local<v8::Object> global0 = context0->Global();

  // Define a property with JS getter and setter.
  CompileRun(
      "function getter() { return 'getter'; };\n"
      "function setter() { return 'setter'; }\n"
      "Object.defineProperty(this, 'js_accessor_p', {get:getter, set:setter})");

  Local<Value> getter =
      global0->Get(context0, v8_str("getter")).ToLocalChecked();
  Local<Value> setter =
      global0->Get(context0, v8_str("setter")).ToLocalChecked();

  // And define normal element.
  CHECK(global0->Set(context0, 239, v8_str("239")).FromJust());

  // Define an element with JS getter and setter.
  CompileRun(
      "function el_getter() { return 'el_getter'; };\n"
      "function el_setter() { return 'el_setter'; };\n"
      "Object.defineProperty(this, '42', {get: el_getter, set: el_setter});");

  Local<Value> el_getter =
      global0->Get(context0, v8_str("el_getter")).ToLocalChecked();
  Local<Value> el_setter =
      global0->Get(context0, v8_str("el_setter")).ToLocalChecked();

  v8::HandleScope scope1(isolate);

  v8::Local<Context> context1 = Context::New(isolate);
  context1->Enter();

  v8::Local<v8::Object> global1 = context1->Global();
  CHECK(global1->Set(context1, v8_str("other"), global0).FromJust());

  // Access blocked property.
  CompileRun("other.blocked_prop = 1");

  CHECK(CompileRun("other.blocked_prop").IsEmpty());
  CHECK(CompileRun("Object.getOwnPropertyDescriptor(other, 'blocked_prop')")
            .IsEmpty());
  CHECK(
      CompileRun("propertyIsEnumerable.call(other, 'blocked_prop')").IsEmpty());

  // Access blocked element.
  CHECK(CompileRun("other[239] = 1").IsEmpty());

  CHECK(CompileRun("other[239]").IsEmpty());
  CHECK(CompileRun("Object.getOwnPropertyDescriptor(other, '239')").IsEmpty());
  CHECK(CompileRun("propertyIsEnumerable.call(other, '239')").IsEmpty());

  allowed_access = true;
  // Now we can enumerate the property.
  ExpectTrue("propertyIsEnumerable.call(other, '239')");
  allowed_access = false;

  // Access a property with JS accessor.
  CHECK(CompileRun("other.js_accessor_p = 2").IsEmpty());

  CHECK(CompileRun("other.js_accessor_p").IsEmpty());
  CHECK(CompileRun("Object.getOwnPropertyDescriptor(other, 'js_accessor_p')")
            .IsEmpty());

  allowed_access = true;

  ExpectString("other.js_accessor_p", "getter");
  ExpectObject(
      "Object.getOwnPropertyDescriptor(other, 'js_accessor_p').get", getter);
  ExpectObject(
      "Object.getOwnPropertyDescriptor(other, 'js_accessor_p').set", setter);
  ExpectUndefined(
      "Object.getOwnPropertyDescriptor(other, 'js_accessor_p').value");

  allowed_access = false;

  // Access an element with JS accessor.
  CHECK(CompileRun("other[42] = 2").IsEmpty());

  CHECK(CompileRun("other[42]").IsEmpty());
  CHECK(CompileRun("Object.getOwnPropertyDescriptor(other, '42')").IsEmpty());

  allowed_access = true;

  ExpectString("other[42]", "el_getter");
  ExpectObject("Object.getOwnPropertyDescriptor(other, '42').get", el_getter);
  ExpectObject("Object.getOwnPropertyDescriptor(other, '42').set", el_setter);
  ExpectUndefined("Object.getOwnPropertyDescriptor(other, '42').value");

  allowed_access = false;

  v8::Local<Value> value;

  // Enumeration doesn't enumerate accessors from inaccessible objects in
  // the prototype chain even if the accessors are in themselves accessible.
  // Enumeration doesn't throw, it silently ignores what it can't access.
  value = CompileRun(
      "(function() {"
      "  var obj = { '__proto__': other };"
      "  try {"
      "    for (var p in obj) {"
      "      if (p == 'blocked_js_prop' ||"
      "          p == 'blocked_js_prop') {"
      "        return false;"
      "      }"
      "    }"
      "    return true;"
      "  } catch (e) {"
      "    return false;"
      "  }"
      "})()");
  CHECK(value->IsTrue());

  // Test that preventExtensions fails on a non-accessible object even if that
  // object is already non-extensible.
  CHECK(global1->Set(context1, v8_str("checked_object"),
                     global_template->NewInstance(context1).ToLocalChecked())
            .FromJust());
  allowed_access = true;
  CompileRun("Object.preventExtensions(checked_object)");
  ExpectFalse("Object.isExtensible(checked_object)");
  allowed_access = false;
  CHECK(CompileRun("Object.preventExtensions(checked_object)").IsEmpty());

  context1->Exit();
  context0->Exit();
}


TEST(AccessControlES5) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);

  global_template->SetAccessCheckCallback(AccessBlocker);

  // Add an accessor that is not accessible by cross-domain JS code.
  global_template->SetNativeDataProperty(v8_str("blocked_prop"),
                                         UnreachableGetter, UnreachableSetter,
                                         v8::Local<Value>());

  // Create an environment
  v8::Local<Context> context0 = Context::New(isolate, nullptr, global_template);
  context0->Enter();

  v8::Local<v8::Object> global0 = context0->Global();

  v8::Local<Context> context1 = Context::New(isolate);
  context1->Enter();
  v8::Local<v8::Object> global1 = context1->Global();
  CHECK(global1->Set(context1, v8_str("other"), global0).FromJust());

  // Regression test for issue 1154.
  CHECK(CompileRun("Object.keys(other).length == 0")->BooleanValue(isolate));
  CHECK(CompileRun("other.blocked_prop").IsEmpty());

  // Regression test for issue 1027.
  CompileRun("Object.defineProperty(\n"
             "  other, 'blocked_prop', {configurable: false})");
  CHECK(CompileRun("other.blocked_prop").IsEmpty());
  CHECK(CompileRun("Object.getOwnPropertyDescriptor(other, 'blocked_prop')")
            .IsEmpty());

  // Regression test for issue 1171.
  ExpectTrue("Object.isExtensible(other)");
  CompileRun("Object.preventExtensions(other)");
  ExpectTrue("Object.isExtensible(other)");

  // Object.seal and Object.freeze.
  CompileRun("Object.freeze(other)");
  ExpectTrue("Object.isExtensible(other)");

  CompileRun("Object.seal(other)");
  ExpectTrue("Object.isExtensible(other)");
}

static bool AccessAlwaysBlocked(Local<v8::Context> accessing_context,
                                Local<v8::Object> global,
                                Local<v8::Value> data) {
  i::PrintF("Access blocked.\n");
  return false;
}

static bool AccessAlwaysAllowed(Local<v8::Context> accessing_context,
                                Local<v8::Object> global,
                                Local<v8::Value> data) {
  i::PrintF("Access allowed.\n");
  return true;
}

TEST(Regress470113) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> obj_template = v8::ObjectTemplate::New(isolate);
  obj_template->SetAccessCheckCallback(AccessAlwaysBlocked);
  LocalContext env;
  CHECK(env->Global()
            ->Set(env.local(), v8_str("prohibited"),
                  obj_template->NewInstance(env.local()).ToLocalChecked())
            .FromJust());

  {
    v8::TryCatch try_catch(isolate);
    CompileRun(
        "'use strict';\n"
        "class C extends Object {\n"
        "   m() { super.powned = 'Powned!'; }\n"
        "}\n"
        "let c = new C();\n"
        "c.m.call(prohibited)");

    CHECK(try_catch.HasCaught());
  }
}

THREADED_TEST(CrossDomainAccessors) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::FunctionTemplate> func_template =
      v8::FunctionTemplate::New(isolate);

  v8::Local<v8::ObjectTemplate> global_template =
      func_template->InstanceTemplate();

  // Add an accessor that is not accessible by cross-domain JS code.
  global_template->SetNativeDataProperty(
      v8_str("unreachable"), UnreachableGetter, nullptr, v8::Local<Value>());

  v8::Local<Context> context0 = Context::New(isolate, nullptr, global_template);
  context0->Enter();

  Local<v8::Object> global = context0->Global();

  // Enter a new context.
  v8::HandleScope scope1(CcTest::isolate());
  v8::Local<Context> context1 = Context::New(isolate);
  context1->Enter();

  v8::Local<v8::Object> global1 = context1->Global();
  CHECK(global1->Set(context1, v8_str("other"), global).FromJust());

  v8::MaybeLocal<v8::Value> maybe_value =
      v8_compile("other.unreachable")->Run(context1);
  CHECK(maybe_value.IsEmpty());

  context1->Exit();
  context0->Exit();
}


static int access_count = 0;

static bool AccessCounter(Local<v8::Context> accessing_context,
                          Local<v8::Object> accessed_object,
                          Local<v8::Value> data) {
  access_count++;
  return true;
}


// This one is too easily disturbed by other tests.
TEST(AccessControlIC) {
  access_count = 0;

  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);

  // Create an environment.
  v8::Local<Context> context0 = Context::New(isolate);
  context0->Enter();

  // Create an object that requires access-check functions to be
  // called for cross-domain access.
  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  object_template->SetAccessCheckCallback(AccessCounter);
  Local<v8::Object> object =
      object_template->NewInstance(context0).ToLocalChecked();

  v8::HandleScope scope1(isolate);

  // Create another environment.
  v8::Local<Context> context1 = Context::New(isolate);
  context1->Enter();

  // Make easy access to the object from the other environment.
  v8::Local<v8::Object> global1 = context1->Global();
  CHECK(global1->Set(context1, v8_str("obj"), object).FromJust());

  v8::Local<Value> value;

  // Check that the named access-control function is called every time.
  CompileRun("function testProp(obj) {"
             "  for (var i = 0; i < 10; i++) obj.prop = 1;"
             "  for (var j = 0; j < 10; j++) obj.prop;"
             "  return obj.prop"
             "}");
  value = CompileRun("testProp(obj)");
  CHECK(value->IsNumber());
  CHECK_EQ(1, value->Int32Value(context1).FromJust());
  CHECK_EQ(21, access_count);

  // Check that the named access-control function is called every time.
  CompileRun("var p = 'prop';"
             "function testKeyed(obj) {"
             "  for (var i = 0; i < 10; i++) obj[p] = 1;"
             "  for (var j = 0; j < 10; j++) obj[p];"
             "  return obj[p];"
             "}");
  // Use obj which requires access checks.  No inline caching is used
  // in that case.
  value = CompileRun("testKeyed(obj)");
  CHECK(value->IsNumber());
  CHECK_EQ(1, value->Int32Value(context1).FromJust());
  CHECK_EQ(42, access_count);
  // Force the inline caches into generic state and try again.
  CompileRun("testKeyed({ a: 0 })");
  CompileRun("testKeyed({ b: 0 })");
  value = CompileRun("testKeyed(obj)");
  CHECK(value->IsNumber());
  CHECK_EQ(1, value->Int32Value(context1).FromJust());
  CHECK_EQ(63, access_count);

  // Check that the indexed access-control function is called every time.
  access_count = 0;

  CompileRun("function testIndexed(obj) {"
             "  for (var i = 0; i < 10; i++) obj[0] = 1;"
             "  for (var j = 0; j < 10; j++) obj[0];"
             "  return obj[0]"
             "}");
  value = CompileRun("testIndexed(obj)");
  CHECK(value->IsNumber());
  CHECK_EQ(1, value->Int32Value(context1).FromJust());
  CHECK_EQ(21, access_count);
  // Force the inline caches into generic state.
  CompileRun("testIndexed(new Array(1))");
  // Test that the indexed access check is called.
  value = CompileRun("testIndexed(obj)");
  CHECK(value->IsNumber());
  CHECK_EQ(1, value->Int32Value(context1).FromJust());
  CHECK_EQ(42, access_count);

  access_count = 0;
  // Check that the named access check is called when invoking
  // functions on an object that requires access checks.
  CompileRun("obj.f = function() {}");
  CompileRun("function testCallNormal(obj) {"
             "  for (var i = 0; i < 10; i++) obj.f();"
             "}");
  CompileRun("testCallNormal(obj)");
  printf("%i\n", access_count);
  CHECK_EQ(11, access_count);

  // Force obj into slow case.
  value = CompileRun("delete obj.prop");
  CHECK(value->BooleanValue(isolate));
  // Force inline caches into dictionary probing mode.
  CompileRun("var o = { x: 0 }; delete o.x; testProp(o);");
  // Test that the named access check is called.
  value = CompileRun("testProp(obj);");
  CHECK(value->IsNumber());
  CHECK_EQ(1, value->Int32Value(context1).FromJust());
  CHECK_EQ(33, access_count);

  // Force the call inline cache into dictionary probing mode.
  CompileRun("o.f = function() {}; testCallNormal(o)");
  // Test that the named access check is still called for each
  // invocation of the function.
  value = CompileRun("testCallNormal(obj)");
  CHECK_EQ(43, access_count);

  context1->Exit();
  context0->Exit();
}


THREADED_TEST(Version) { v8::V8::GetVersion(); }


static void InstanceFunctionCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  args.GetReturnValue().Set(v8_num(12));
}


THREADED_TEST(InstanceProperties) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
  Local<ObjectTemplate> instance = t->InstanceTemplate();

  instance->Set(isolate, "x", v8_num(42));
  instance->Set(isolate, "f",
                v8::FunctionTemplate::New(isolate, InstanceFunctionCallback));

  Local<Value> o = t->GetFunction(context.local())
                       .ToLocalChecked()
                       ->NewInstance(context.local())
                       .ToLocalChecked();

  CHECK(context->Global()->Set(context.local(), v8_str("i"), o).FromJust());
  Local<Value> value = CompileRun("i.x");
  CHECK_EQ(42, value->Int32Value(context.local()).FromJust());

  value = CompileRun("i.f()");
  CHECK_EQ(12, value->Int32Value(context.local()).FromJust());
}

namespace {
v8::Intercepted GlobalObjectInstancePropertiesGet(
    Local<Name> key, const v8::PropertyCallbackInfo<v8::Value>& info) {
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CHECK(i::ValidateCallbackInfo(info));
  return v8::Intercepted::kNo;
}

int script_execution_count = 0;
void ScriptExecutionCallback(v8::Isolate* isolate, Local<Context> context) {
  script_execution_count++;
}
}  // namespace

THREADED_TEST(ContextScriptExecutionCallback) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  LocalContext context;

  {
    v8::TryCatch try_catch(isolate);
    script_execution_count = 0;
    ExpectTrue("1 + 1 == 2");
    CHECK_EQ(0, script_execution_count);
    CHECK(!try_catch.HasCaught());
  }

  context->SetAbortScriptExecution(ScriptExecutionCallback);

  {  // Function binding does not trigger callback.
    v8::Local<v8::FunctionTemplate> function_template =
        v8::FunctionTemplate::New(isolate, DummyCallHandler);
    v8::Local<v8::Function> function =
        function_template->GetFunction(context.local()).ToLocalChecked();

    v8::TryCatch try_catch(isolate);
    script_execution_count = 0;

    CHECK_EQ(13.4,
             function->Call(context.local(), v8::Undefined(isolate), 0, nullptr)
                 .ToLocalChecked()
                 ->NumberValue(context.local())
                 .FromJust());
    CHECK_EQ(0, script_execution_count);
    CHECK(!try_catch.HasCaught());
  }

  {  // Script execution triggers callback.
    v8::TryCatch try_catch(isolate);
    script_execution_count = 0;
    CHECK(CompileRun(context.local(), "2 + 2 == 4").IsEmpty());
    CHECK_EQ(1, script_execution_count);
    CHECK(try_catch.HasCaught());
  }

  context->SetAbortScriptExecution(nullptr);

  {  // Script execution no longer triggers callback.
    v8::TryCatch try_catch(isolate);
    script_execution_count = 0;
    ExpectTrue("2 + 2 == 4");
    CHECK_EQ(0, script_execution_count);
    CHECK(!try_catch.HasCaught());
  }
}

THREADED_TEST(GlobalObjectInstanceProperties) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);

  Local<Value> global_object;

  Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
  t->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(GlobalObjectInstancePropertiesGet));
  Local<ObjectTemplate> instance_template = t->InstanceTemplate();
  instance_template->Set(isolate, "x", v8_num(42));
  instance_template->Set(
      isolate, "f",
      v8::FunctionTemplate::New(isolate, InstanceFunctionCallback));

  // The script to check how TurboFan compiles missing global function
  // invocations.  function g is not defined and should throw on call.
  const char* script =
      "function wrapper(call) {"
      "  var x = 0, y = 1;"
      "  for (var i = 0; i < 1000; i++) {"
      "    x += i * 100;"
      "    y += i * 100;"
      "  }"
      "  if (call) g();"
      "}"
      "for (var i = 0; i < 17; i++) wrapper(false);"
      "var thrown = 0;"
      "try { wrapper(true); } catch (e) { thrown = 1; };"
      "thrown";

  {
    LocalContext env(nullptr, instance_template);
    // Hold on to the global object so it can be used again in another
    // environment initialization.
    global_object = env->Global();

    Local<Value> value = CompileRun("x");
    CHECK_EQ(42, value->Int32Value(env.local()).FromJust());
    value = CompileRun("f()");
    CHECK_EQ(12, value->Int32Value(env.local()).FromJust());
    value = CompileRun(script);
    CHECK_EQ(1, value->Int32Value(env.local()).FromJust());
  }

  {
    // Create new environment reusing the global object.
    LocalContext env(nullptr, instance_template, global_object);
    Local<Value> value = CompileRun("x");
    CHECK_EQ(42, value->Int32Value(env.local()).FromJust());
    value = CompileRun("f()");
    CHECK_EQ(12, value->Int32Value(env.local()).FromJust());
    value = CompileRun(script);
    CHECK_EQ(1, value->Int32Value(env.local()).FromJust());
  }
}

THREADED_TEST(ObjectGetOwnPropertyNames) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Object> value = v8::Local<v8::Object>::Cast(
      v8::StringObject::New(CcTest::isolate(), v8_str("test")));
  v8::Local<v8::Array> properties;

  CHECK(value
            ->GetOwnPropertyNames(context.local(),
                                  static_cast<v8::PropertyFilter>(
                                      v8::PropertyFilter::ALL_PROPERTIES |
                                      v8::PropertyFilter::SKIP_SYMBOLS),
                                  v8::KeyConversionMode::kKeepNumbers)
            .ToLocal(&properties));
  CHECK_EQ(5u, properties->Length());
  v8::Local<v8::Value> property;
  CHECK(properties->Get(context.local(), 4).ToLocal(&property) &&
        property->IsString());
  CHECK(property.As<v8::String>()
            ->Equals(context.local(), v8_str("length"))
            .FromMaybe(false));
  for (int i = 0; i < 4; ++i) {
    CHECK(properties->Get(context.local(), i).ToLocal(&property) &&
          property->IsInt32());
    CHECK_EQ(property.As<v8::Int32>()->Value(), i);
  }

  CHECK(value
            ->GetOwnPropertyNames(context.local(),
                                  v8::PropertyFilter::ONLY_ENUMERABLE,
                                  v8::KeyConversionMode::kKeepNumbers)
            .ToLocal(&properties));
  v8::Local<v8::Array> number_properties;
  CHECK(value
            ->GetOwnPropertyNames(context.local(),
                                  v8::PropertyFilter::ONLY_ENUMERABLE,
                                  v8::KeyConversionMode::kConvertToString)
            .ToLocal(&number_properties));
  CHECK_EQ(4u, properties->Length());
  for (int i = 0; i < 4; ++i) {
    v8::Local<v8::Value> property_index;
    v8::Local<v8::Value> property_name;

    CHECK(number_properties->Get(context.local(), i).ToLocal(&property_name));
    CHECK(property_name->IsString());

    CHECK(properties->Get(context.local(), i).ToLocal(&property_index));
    CHECK(property_index->IsInt32());

    CHECK_EQ(property_index.As<v8::Int32>()->Value(), i);
    CHECK_EQ(property_name->ToNumber(context.local())
                 .ToLocalChecked()
                 .As<v8::Int32>()
                 ->Value(),
             i);
  }

  value = value->GetPrototypeV2().As<v8::Object>();
  CHECK(value
            ->GetOwnPropertyNames(context.local(),
                                  static_cast<v8::PropertyFilter>(
                                      v8::PropertyFilter::ALL_PROPERTIES |
                                      v8::PropertyFilter::SKIP_SYMBOLS))
            .ToLocal(&properties));
  bool concat_found = false;
  bool starts_with_found = false;
  for (uint32_t i = 0; i < properties->Length(); ++i) {
    CHECK(properties->Get(context.local(), i).ToLocal(&property));
    if (!property->IsString()) continue;
    if (!concat_found)
      concat_found = property.As<v8::String>()
                         ->Equals(context.local(), v8_str("concat"))
                         .FromMaybe(false);
    if (!starts_with_found)
      starts_with_found = property.As<v8::String>()
                              ->Equals(context.local(), v8_str("startsWith"))
                              .FromMaybe(false);
  }
  CHECK(concat_found && starts_with_found);
}

THREADED_TEST(CallKnownGlobalReceiver) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);

  Local<Value> global_object;

  Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
  Local<ObjectTemplate> instance_template = t->InstanceTemplate();

  // The script to check that we leave global object not
  // global object proxy on stack when we deoptimize from inside
  // arguments evaluation.
  // To provoke error we need to both force deoptimization
  // from arguments evaluation and to force CallIC to take
  // CallIC_Miss code path that can't cope with global proxy.
  const char* script =
      "function bar(x, y) { try { } finally { } }"
      "function baz(x) { try { } finally { } }"
      "function bom(x) { try { } finally { } }"
      "function foo(x) { bar([x], bom(2)); }"
      "for (var i = 0; i < 10000; i++) foo(1);"
      "foo";

  Local<Value> foo;
  {
    LocalContext env(nullptr, instance_template);
    // Hold on to the global object so it can be used again in another
    // environment initialization.
    global_object = env->Global();
    foo = CompileRun(script);
  }

  {
    // Create new environment reusing the global object.
    LocalContext env(nullptr, instance_template, global_object);
    CHECK(env->Global()->Set(env.local(), v8_str("foo"), foo).FromJust());
    CompileRun("foo()");
  }
}

namespace {
void ShadowFunctionCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  args.GetReturnValue().Set(v8_num(42));
}

int shadow_y;
int shadow_y_setter_call_count;
int shadow_y_getter_call_count;

void ShadowYSetter(Local<Name>, Local<Value>,
                   const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  shadow_y_setter_call_count++;
  shadow_y = 42;
}

void ShadowYGetter(Local<Name> name,
                   const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  shadow_y_getter_call_count++;
  info.GetReturnValue().Set(v8_num(shadow_y));
}

v8::Intercepted ShadowIndexedGet(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  return v8::Intercepted::kNo;
}

v8::Intercepted ShadowNamedGet(
    Local<Name> key, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  return v8::Intercepted::kNo;
}
}  // namespace

THREADED_TEST(ShadowObject) {
  shadow_y = shadow_y_setter_call_count = shadow_y_getter_call_count = 0;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);

  Local<ObjectTemplate> global_template = v8::ObjectTemplate::New(isolate);
  LocalContext context(nullptr, global_template);

  Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
  t->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(ShadowNamedGet));
  t->InstanceTemplate()->SetHandler(
      v8::IndexedPropertyHandlerConfiguration(ShadowIndexedGet));
  Local<ObjectTemplate> proto = t->PrototypeTemplate();
  Local<ObjectTemplate> instance = t->InstanceTemplate();

  proto->Set(isolate, "f",
             v8::FunctionTemplate::New(isolate, ShadowFunctionCallback,
                                       Local<Value>()));
  proto->Set(isolate, "x", v8_num(12));

  instance->SetNativeDataProperty(v8_str("y"), ShadowYGetter, ShadowYSetter);

  Local<Value> o = t->GetFunction(context.local())
                       .ToLocalChecked()
                       ->NewInst
"""


```