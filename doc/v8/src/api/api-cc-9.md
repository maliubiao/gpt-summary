Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/api/api.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Task:** The primary goal is to understand what the given C++ code does within the V8 JavaScript engine.

2. **Scan for Key Concepts and Classes:** Quickly read through the code, looking for V8 API classes and functions like `Context`, `ObjectTemplate`, `FunctionTemplate`, `String`, `RegExp`, `Date`, etc. These names hint at the areas of functionality being covered.

3. **Group Functionality:**  As key elements are identified, start grouping related functions. For example, the code related to `Context` manipulates promise hooks and template literal objects. The code involving `ObjectTemplate`, `FunctionTemplate`, `DictionaryTemplate`, and `Signature` deals with creating and checking the types of template objects used to define JavaScript objects and functions. String manipulation functions are also clearly present.

4. **Analyze Individual Code Blocks:** For each identified group, examine the specific functions and their logic.
    * **Promise Hooks:** The `Context::SetPromiseHook` function clearly sets up hooks for different stages of promise execution. The conditional compilation (`#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS`) is important to note.
    * **Template Literal Objects:** `Context::HasTemplateLiteralObject` checks if a given object is a template literal.
    * **Metrics Recording:** The `metrics::Recorder` functions manage context IDs for performance tracking.
    * **Snapshot Data:** `Context::GetDataFromSnapshotOnce` retrieves serialized data.
    * **Templates:**  The `*Template::NewInstance` and `*Template::GetFunction` methods create new instances of objects and functions based on templates. The `*Template::CheckCast` methods perform type checking.
    * **Remote Instances:** `FunctionTemplate::NewRemoteInstance` seems to create objects in a different context or isolate, focusing on security with access checks.
    * **Instance Checking:** `FunctionTemplate::HasInstance` and `FunctionTemplate::IsLeafTemplateForApiObject` are used to check if an object is an instance of a particular function template.
    * **External Values:** `External::New` and `External::Value` deal with wrapping C++ pointers for use in JavaScript.
    * **String Creation:** The `String::NewFrom*` family of functions provides various ways to create JavaScript strings from C++ data. The helper functions and macros simplify this. Pay attention to different encodings (UTF-8, one-byte, two-byte) and internalization.
    * **String Manipulation:** `String::Concat`, `String::MakeExternal`, and `String::StringEquals` are standard string operations.
    * **Object Creation:** The `Object::New` overloads demonstrate different ways to create JavaScript objects, including setting prototypes and properties. The handling of array indices and property dictionaries is relevant.
    * **Primitive Objects:** `NumberObject`, `BigIntObject`, `BooleanObject`, `StringObject`, and `SymbolObject` show how to create wrapper objects for primitive JavaScript types.
    * **Date Object:** `Date::New`, `Date::Parse`, `Date::ValueOf`, `Date::ToISOString`, and `Date::ToUTCString` cover the creation, parsing, and formatting of JavaScript Date objects.
    * **RegExp Object:** `RegExp::New`, `RegExp::NewWithBacktrackLimit`, `RegExp::GetSource`, `RegExp::GetFlags`, and `RegExp::Exec` handle the creation and execution of regular expressions.

5. **Address Specific Instructions:**
    * **`.tq` Extension:** Explicitly state that the file is `.cc` and not `.tq`, thus not Torque code.
    * **JavaScript Relationship:** For each functional area, connect it to its corresponding JavaScript concept and provide a simple JavaScript example where applicable.
    * **Code Logic Inference:**  Where the code performs logical checks or data manipulation (like promise hooks or string creation with length checks), describe the assumed input and output.
    * **Common Programming Errors:** Think about how developers might misuse the APIs and provide examples of typical mistakes (e.g., passing null to `External::New`, exceeding string length limits).
    * **Part of Series:** Acknowledge that this is part 10 of 15 and that the summary focuses solely on the given snippet.

6. **Structure the Response:** Organize the findings logically, using headings and bullet points for clarity. Start with a general summary, then detail each functional area.

7. **Refine and Review:**  Read through the generated summary, ensuring it's accurate, comprehensive, and easy to understand. Check for any inconsistencies or omissions. Ensure the JavaScript examples are correct and illustrate the point. Make sure the assumptions, inputs, and outputs for logic inference are clear.

By following this process, the detailed and informative summary of the `v8/src/api/api.cc` code snippet can be constructed.
这是 V8 源代码文件 `v8/src/api/api.cc` 的一部分，主要负责实现 V8 引擎的公共 API。 这部分代码涵盖了多种 V8 功能的 C++ 接口，允许开发者在 C++ 代码中与 V8 引擎进行交互。

**功能归纳:**

这段代码主要提供了以下功能的 C++ 接口：

1. **Promise Hook 管理:**  允许设置 Promise 的初始化、before、after 和 resolve 等阶段的回调函数，用于监控和调试 Promise 的执行。
2. **模板字面量对象检查:** 提供方法判断一个对象是否是模板字面量对象。
3. **上下文 (Context) 和指标 (Metrics) 管理:** 提供获取和注册上下文 ID 的功能，用于性能指标的记录。
4. **长任务统计:**  提供获取当前长任务统计信息的功能。
5. **快照数据访问:** 允许从快照中获取序列化对象的数据。
6. **模板 (Template) 操作:**
    * 创建对象模板和函数模板的新实例。
    * 检查对象的类型是否是特定的模板类型 (ObjectTemplate, DictionaryTemplate, FunctionTemplate, Signature)。
    * 获取函数模板对应的 JavaScript 函数。
    * 创建远程对象实例 (可能用于隔离的上下文)。
    * 判断一个值是否是某个函数模板的实例。
    * 判断一个值是否是 API 对象的叶子模板。
7. **外部数据 (External) 管理:**  允许创建包含 C++ 指针的外部对象，并在 JavaScript 中使用。
8. **字符串 (String) 操作:**
    * 创建各种类型的 JavaScript 字符串 (UTF-8, OneByte, TwoByte, 字面量)。
    * 连接字符串。
    * 创建指向外部资源的字符串。
    * 将内部字符串转换为外部字符串。
    * 判断两个字符串是否相等。
9. **对象 (Object) 操作:**
    * 创建新的 JavaScript 对象。
    * 创建具有指定原型和属性的对象。
10. **原始值对象 (Primitive Object) 创建:**  创建 NumberObject, BigIntObject, BooleanObject, StringObject 和 SymbolObject 等包装原始值的对象。
11. **日期 (Date) 操作:**
    * 创建新的 Date 对象。
    * 解析字符串为 Date 对象。
    * 获取 Date 对象的值 (时间戳)。
    * 将 Date 对象转换为 ISO 和 UTC 字符串。
12. **正则表达式 (RegExp) 操作:**
    * 创建新的 RegExp 对象，可以设置回溯限制。
    * 获取正则表达式的源字符串和标志。
    * 执行正则表达式匹配。

**关于源代码类型:**

`v8/src/api/api.cc` 的文件扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**，而不是以 `.tq` 结尾的 Torque 源代码文件。 Torque 是一种 V8 内部使用的类型化的汇编语言，用于实现性能关键的代码。

**与 JavaScript 的关系及示例:**

该文件中的 C++ 代码直接对应着 JavaScript 中可以使用的 API。以下是一些功能的 JavaScript 示例：

1. **Promise Hook 管理:**

```javascript
// 需要在 V8 启动时或通过特定的 API 设置 PromiseHook
// 假设在 C++ 中已经设置了这些 hook

const promise = new Promise((resolve, reject) => {
  // ... 一些异步操作
  resolve(10);
});

promise.then(result => {
  console.log('Promise resolved with:', result);
});
```

当上述 JavaScript 代码执行时，如果在 C++ 中通过 `Context::SetPromiseHook` 设置了相应的回调函数，这些回调函数将在 Promise 的不同阶段被触发。

2. **模板字面量对象检查:**

虽然没有直接的 JavaScript API 来调用 `HasTemplateLiteralObject`，但模板字面量在 JavaScript 中是这样使用的：

```javascript
const name = 'World';
const greeting = `Hello, ${name}!`; // greeting 是一个包含模板字面量的字符串
```

V8 内部可能会使用 `HasTemplateLiteralObject` 来识别和处理这种类型的对象。

3. **对象创建:**

```javascript
const obj1 = {}; // 使用 Object::New() 的默认形式
const proto = { z: 3 };
const obj2 = Object.create(proto); // 使用 Object::New(prototype_or_null)

const obj3 = { x: 1, y: 2 }; // 使用 Object::New(prototype_or_null, names, values, length) 的一种体现
```

4. **字符串创建:**

```javascript
const str1 = 'hello'; // 对应 String::NewFromUtf8Literal 或类似函数
const str2 = new String('world'); // 对应 StringObject::New
```

5. **日期操作:**

```javascript
const now = new Date(); // 对应 Date::New
const parsedDate = Date.parse('2023-10-27'); // 对应 Date::Parse
console.log(now.toISOString()); // 对应 Date::ToISOString
```

6. **正则表达式操作:**

```javascript
const regex1 = /abc/g; // 对应 RegExp::New
const match = regex1.exec('abcdef'); // 对应 RegExp::Exec
```

**代码逻辑推理:**

**假设输入:**

* `init_hook`, `before_hook`, `after_hook`, `resolve_hook` 是代表 JavaScript 函数的 `v8::Local<v8::Value>` 对象，它们可以为空。

**输出:**

* 如果 `V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS` 宏被定义，并且至少有一个 hook 被设置（非空），则会调用 `i_isolate->SetHasContextPromiseHooks(true)`，并且相应的 hook 函数会被设置到当前上下文的 `native_context` 中。
* 如果 `V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS` 宏未被定义，则会触发一个断言失败的 API 检查错误。

**用户常见的编程错误:**

1. **在未启用 Promise Hook 的编译版本中使用 `Context::SetPromiseHook`:**  如果 V8 的编译配置中没有启用 JavaScript Promise hooks，调用此方法会导致运行时错误或断言失败。

   ```c++
   // 假设 V8 编译时未启用 Promise Hook
   v8::Local<v8::Context> context = ...;
   v8::Local<v8::Function> init_fn = ...;
   context->SetPromiseHook(init_fn, v8::Local<v8::Function>(), v8::Local<v8::Function>(), v8::Local<v8::Function>()); // 错误，V8 会报错
   ```

2. **字符串长度超过限制:** 尝试创建非常长的字符串可能会失败。

   ```c++
   v8::Isolate* isolate = ...;
   v8::Isolate::Scope isolate_scope(isolate);
   v8::HandleScope handle_scope(isolate);
   v8::Local<v8::Context> context = v8::Context::New(isolate);
   v8::Context::Scope context_scope(context);

   std::string long_string(v8::String::kMaxLength + 1, 'a');
   v8::Local<v8::String> str = v8::String::NewFromUtf8(isolate, long_string.c_str()); // 可能返回空值
   if (str.IsEmpty()) {
       // 处理字符串创建失败的情况
   }
   ```

3. **错误地假设模板类型:**  使用 `CheckCast` 前未正确判断对象类型可能导致程序崩溃或未定义的行为。

   ```c++
   v8::Local<v8::Data> data = ...;
   // 错误地假设 data 是一个 FunctionTemplate
   v8::FunctionTemplate::CheckCast(static_cast<v8::FunctionTemplate::Data*>(*data)); // 如果 data 不是 FunctionTemplate，会导致错误
   ```

**第 10 部分，共 15 部分的功能归纳:**

作为第 10 部分，这段代码集中展示了 V8 引擎 API 的核心功能，包括上下文管理、对象和函数模板操作、字符串处理、原始值对象的创建以及日期和正则表达式的处理。 它体现了 V8 如何将底层的 C++ 实现暴露给 JavaScript 环境，使得开发者可以通过 C++ 代码来扩展和集成 V8 引擎。 这部分代码是 V8 API 的重要组成部分，为 V8 的嵌入和扩展提供了基础。

Prompt: 
```
这是目录为v8/src/api/api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第10部分，共15部分，请归纳一下它的功能

"""
actory()->undefined_value();
  i::DirectHandle<i::Object> init = undefined;
  i::DirectHandle<i::Object> before = undefined;
  i::DirectHandle<i::Object> after = undefined;
  i::DirectHandle<i::Object> resolve = undefined;

  bool has_hook = false;

  if (!init_hook.IsEmpty()) {
    init = Utils::OpenDirectHandle(*init_hook);
    has_hook = true;
  }
  if (!before_hook.IsEmpty()) {
    before = Utils::OpenDirectHandle(*before_hook);
    has_hook = true;
  }
  if (!after_hook.IsEmpty()) {
    after = Utils::OpenDirectHandle(*after_hook);
    has_hook = true;
  }
  if (!resolve_hook.IsEmpty()) {
    resolve = Utils::OpenDirectHandle(*resolve_hook);
    has_hook = true;
  }

  i_isolate->SetHasContextPromiseHooks(has_hook);

  context->native_context()->set_promise_hook_init_function(*init);
  context->native_context()->set_promise_hook_before_function(*before);
  context->native_context()->set_promise_hook_after_function(*after);
  context->native_context()->set_promise_hook_resolve_function(*resolve);
#else   // V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
  Utils::ApiCheck(false, "v8::Context::SetPromiseHook",
                  "V8 was compiled without JavaScript Promise hooks");
#endif  // V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
}

bool Context::HasTemplateLiteralObject(Local<Value> object) {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::Object> i_object = *Utils::OpenDirectHandle(*object);
  if (!IsJSArray(i_object)) return false;
  return Utils::OpenDirectHandle(this)
      ->native_context()
      ->HasTemplateLiteralObject(i::Cast<i::JSArray>(i_object));
}

MaybeLocal<Context> metrics::Recorder::GetContext(
    Isolate* v8_isolate, metrics::Recorder::ContextId id) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  return i_isolate->GetContextFromRecorderContextId(id);
}

metrics::Recorder::ContextId metrics::Recorder::GetContextId(
    Local<Context> context) {
  auto i_context = Utils::OpenDirectHandle(*context);
  i::Isolate* i_isolate = i_context->GetIsolate();
  return i_isolate->GetOrRegisterRecorderContextId(
      handle(i_context->native_context(), i_isolate));
}

metrics::LongTaskStats metrics::LongTaskStats::Get(v8::Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  return *i_isolate->GetCurrentLongTaskStats();
}

namespace {
i::ValueHelper::InternalRepresentationType GetSerializedDataFromFixedArray(
    i::Isolate* i_isolate, i::Tagged<i::FixedArray> list, size_t index) {
  if (index < static_cast<size_t>(list->length())) {
    int int_index = static_cast<int>(index);
    i::Tagged<i::Object> object = list->get(int_index);
    if (!IsTheHole(object, i_isolate)) {
      list->set_the_hole(i_isolate, int_index);
      // Shrink the list so that the last element is not the hole (unless it's
      // the first element, because we don't want to end up with a non-canonical
      // empty FixedArray).
      int last = list->length() - 1;
      while (last >= 0 && list->is_the_hole(i_isolate, last)) last--;
      if (last != -1) list->RightTrim(i_isolate, last + 1);
      return i::Handle<i::Object>(object, i_isolate).repr();
    }
  }
  return i::ValueHelper::kEmpty;
}
}  // anonymous namespace

i::ValueHelper::InternalRepresentationType Context::GetDataFromSnapshotOnce(
    size_t index) {
  auto context = Utils::OpenHandle(this);
  i::Isolate* i_isolate = context->GetIsolate();
  auto list = i::Cast<i::FixedArray>(context->serialized_objects());
  return GetSerializedDataFromFixedArray(i_isolate, list, index);
}

MaybeLocal<v8::Object> ObjectTemplate::NewInstance(Local<Context> context) {
  PREPARE_FOR_EXECUTION(context, ObjectTemplate, NewInstance);
  auto self = Utils::OpenHandle(this);
  Local<Object> result;
  has_exception = !ToLocal<Object>(
      i::ApiNatives::InstantiateObject(i_isolate, self), &result);
  RETURN_ON_FAILED_EXECUTION(Object);
  RETURN_ESCAPED(result);
}

void v8::ObjectTemplate::CheckCast(Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsObjectTemplateInfo(*obj), "v8::ObjectTemplate::Cast",
                  "Value is not an ObjectTemplate");
}

void v8::DictionaryTemplate::CheckCast(Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsDictionaryTemplateInfo(*obj),
                  "v8::DictionaryTemplate::Cast",
                  "Value is not an DictionaryTemplate");
}

void v8::FunctionTemplate::CheckCast(Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsFunctionTemplateInfo(*obj), "v8::FunctionTemplate::Cast",
                  "Value is not a FunctionTemplate");
}

void v8::Signature::CheckCast(Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsFunctionTemplateInfo(*obj), "v8::Signature::Cast",
                  "Value is not a Signature");
}

MaybeLocal<v8::Function> FunctionTemplate::GetFunction(Local<Context> context) {
  PREPARE_FOR_EXECUTION(context, FunctionTemplate, GetFunction);
  auto self = Utils::OpenHandle(this);
  Local<Function> result;
  has_exception =
      !ToLocal<Function>(i::ApiNatives::InstantiateFunction(
                             i_isolate, i_isolate->native_context(), self),
                         &result);
  RETURN_ON_FAILED_EXECUTION(Function);
  RETURN_ESCAPED(result);
}

MaybeLocal<v8::Object> FunctionTemplate::NewRemoteInstance() {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolateChecked();
  API_RCS_SCOPE(i_isolate, FunctionTemplate, NewRemoteInstance);
  i::HandleScope scope(i_isolate);
  i::DirectHandle<i::FunctionTemplateInfo> constructor =
      EnsureConstructor(i_isolate, *InstanceTemplate());
  Utils::ApiCheck(constructor->needs_access_check(),
                  "v8::FunctionTemplate::NewRemoteInstance",
                  "InstanceTemplate needs to have access checks enabled");
  i::DirectHandle<i::AccessCheckInfo> access_check_info(
      i::Cast<i::AccessCheckInfo>(constructor->GetAccessCheckInfo()),
      i_isolate);
  Utils::ApiCheck(
      access_check_info->named_interceptor() != i::Tagged<i::Object>(),
      "v8::FunctionTemplate::NewRemoteInstance",
      "InstanceTemplate needs to have access check handlers");
  i::Handle<i::JSObject> object;
  if (!i::ApiNatives::InstantiateRemoteObject(
           Utils::OpenHandle(*InstanceTemplate()))
           .ToHandle(&object)) {
    return MaybeLocal<Object>();
  }
  return Utils::ToLocal(scope.CloseAndEscape(object));
}

bool FunctionTemplate::HasInstance(v8::Local<v8::Value> value) {
  auto self = Utils::OpenDirectHandle(this);
  auto obj = Utils::OpenDirectHandle(*value);
  if (i::IsJSObject(*obj) && self->IsTemplateFor(i::Cast<i::JSObject>(*obj))) {
    return true;
  }
  if (i::IsJSGlobalProxy(*obj)) {
    // If it's a global proxy, then test with the global object. Note that the
    // inner global object may not necessarily be a JSGlobalObject.
    auto jsobj = i::Cast<i::JSObject>(*obj);
    i::PrototypeIterator iter(jsobj->GetIsolate(), jsobj->map());
    // The global proxy should always have a prototype, as it is a bug to call
    // this on a detached JSGlobalProxy.
    DCHECK(!iter.IsAtEnd());
    return self->IsTemplateFor(iter.GetCurrent<i::JSObject>());
  }
  return false;
}

bool FunctionTemplate::IsLeafTemplateForApiObject(
    v8::Local<v8::Value> value) const {
  i::DisallowGarbageCollection no_gc;
  auto self = Utils::OpenDirectHandle(this);
  i::Tagged<i::Object> object = *Utils::OpenDirectHandle(*value);
  return self->IsLeafTemplateForApiObject(object);
}

Local<External> v8::External::New(Isolate* v8_isolate, void* value) {
  static_assert(sizeof(value) == sizeof(i::Address));
  // Nullptr is not allowed here because serialization/deserialization of
  // nullptr external api references is not possible as nullptr is used as an
  // external_references table terminator, see v8::SnapshotCreator()
  // constructors.
  DCHECK_NOT_NULL(value);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, External, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::JSObject> external = i_isolate->factory()->NewExternal(value);
  return Utils::ExternalToLocal(external);
}

void* External::Value() const {
  return i::Cast<i::JSExternalObject>(*Utils::OpenDirectHandle(this))->value();
}

// anonymous namespace for string creation helper functions
namespace {

inline int StringLength(const char* string) {
  size_t len = strlen(string);
  CHECK_GE(i::kMaxInt, len);
  return static_cast<int>(len);
}

inline int StringLength(const uint8_t* string) {
  return StringLength(reinterpret_cast<const char*>(string));
}

inline int StringLength(const uint16_t* string) {
  size_t length = 0;
  while (string[length] != '\0') length++;
  CHECK_GE(i::kMaxInt, length);
  return static_cast<int>(length);
}

V8_WARN_UNUSED_RESULT
inline i::MaybeHandle<i::String> NewString(i::Factory* factory,
                                           NewStringType type,
                                           base::Vector<const char> string) {
  if (type == NewStringType::kInternalized) {
    return factory->InternalizeUtf8String(string);
  }
  return factory->NewStringFromUtf8(string);
}

V8_WARN_UNUSED_RESULT
inline i::MaybeHandle<i::String> NewString(i::Factory* factory,
                                           NewStringType type,
                                           base::Vector<const uint8_t> string) {
  if (type == NewStringType::kInternalized) {
    return factory->InternalizeString(string);
  }
  return factory->NewStringFromOneByte(string);
}

V8_WARN_UNUSED_RESULT
inline i::MaybeHandle<i::String> NewString(
    i::Factory* factory, NewStringType type,
    base::Vector<const uint16_t> string) {
  if (type == NewStringType::kInternalized) {
    return factory->InternalizeString(string);
  }
  return factory->NewStringFromTwoByte(string);
}

static_assert(v8::String::kMaxLength == i::String::kMaxLength);

}  // anonymous namespace

// TODO(dcarney): throw a context free exception.
#define NEW_STRING(v8_isolate, class_name, function_name, Char, data, type,   \
                   length)                                                    \
  MaybeLocal<String> result;                                                  \
  if (length == 0) {                                                          \
    result = String::Empty(v8_isolate);                                       \
  } else if (length > 0 &&                                                    \
             static_cast<uint32_t>(length) > i::String::kMaxLength) {         \
    result = MaybeLocal<String>();                                            \
  } else {                                                                    \
    i::Isolate* i_isolate = reinterpret_cast<internal::Isolate*>(v8_isolate); \
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);                               \
    API_RCS_SCOPE(i_isolate, class_name, function_name);                      \
    if (length < 0) length = StringLength(data);                              \
    i::Handle<i::String> handle_result =                                      \
        NewString(i_isolate->factory(), type,                                 \
                  base::Vector<const Char>(data, length))                     \
            .ToHandleChecked();                                               \
    result = Utils::ToLocal(handle_result);                                   \
  }

Local<String> String::NewFromUtf8Literal(Isolate* v8_isolate,
                                         const char* literal,
                                         NewStringType type, int length) {
  DCHECK_LE(length, i::String::kMaxLength);
  i::Isolate* i_isolate = reinterpret_cast<internal::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  API_RCS_SCOPE(i_isolate, String, NewFromUtf8Literal);
  i::Handle<i::String> handle_result =
      NewString(i_isolate->factory(), type,
                base::Vector<const char>(literal, length))
          .ToHandleChecked();
  return Utils::ToLocal(handle_result);
}

MaybeLocal<String> String::NewFromUtf8(Isolate* v8_isolate, const char* data,
                                       NewStringType type, int length) {
  NEW_STRING(v8_isolate, String, NewFromUtf8, char, data, type, length);
  return result;
}

MaybeLocal<String> String::NewFromOneByte(Isolate* v8_isolate,
                                          const uint8_t* data,
                                          NewStringType type, int length) {
  NEW_STRING(v8_isolate, String, NewFromOneByte, uint8_t, data, type, length);
  return result;
}

MaybeLocal<String> String::NewFromTwoByte(Isolate* v8_isolate,
                                          const uint16_t* data,
                                          NewStringType type, int length) {
  NEW_STRING(v8_isolate, String, NewFromTwoByte, uint16_t, data, type, length);
  return result;
}

Local<String> v8::String::Concat(Isolate* v8_isolate, Local<String> left,
                                 Local<String> right) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto left_string = Utils::OpenHandle(*left);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  API_RCS_SCOPE(i_isolate, String, Concat);
  auto right_string = Utils::OpenHandle(*right);
  // If we are steering towards a range error, do not wait for the error to be
  // thrown, and return the null handle instead.
  if (left_string->length() + right_string->length() > i::String::kMaxLength) {
    return Local<String>();
  }
  i::Handle<i::String> result = i_isolate->factory()
                                    ->NewConsString(left_string, right_string)
                                    .ToHandleChecked();
  return Utils::ToLocal(result);
}

MaybeLocal<String> v8::String::NewExternalTwoByte(
    Isolate* v8_isolate, v8::String::ExternalStringResource* resource) {
  CHECK(resource && resource->data());
  // TODO(dcarney): throw a context free exception.
  if (resource->length() > static_cast<size_t>(i::String::kMaxLength)) {
    return MaybeLocal<String>();
  }
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  API_RCS_SCOPE(i_isolate, String, NewExternalTwoByte);
  if (resource->length() > 0) {
    i::Handle<i::String> string = i_isolate->factory()
                                      ->NewExternalStringFromTwoByte(resource)
                                      .ToHandleChecked();
    return Utils::ToLocal(string);
  } else {
    // The resource isn't going to be used, free it immediately.
    resource->Unaccount(v8_isolate);
    resource->Dispose();
    return Utils::ToLocal(i_isolate->factory()->empty_string());
  }
}

MaybeLocal<String> v8::String::NewExternalOneByte(
    Isolate* v8_isolate, v8::String::ExternalOneByteStringResource* resource) {
  CHECK_NOT_NULL(resource);
  // TODO(dcarney): throw a context free exception.
  if (resource->length() > static_cast<size_t>(i::String::kMaxLength)) {
    return MaybeLocal<String>();
  }
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  API_RCS_SCOPE(i_isolate, String, NewExternalOneByte);
  if (resource->length() == 0) {
    // The resource isn't going to be used, free it immediately.
    resource->Unaccount(v8_isolate);
    resource->Dispose();
    return Utils::ToLocal(i_isolate->factory()->empty_string());
  }
  CHECK_NOT_NULL(resource->data());
  i::Handle<i::String> string = i_isolate->factory()
                                    ->NewExternalStringFromOneByte(resource)
                                    .ToHandleChecked();
  return Utils::ToLocal(string);
}

bool v8::String::MakeExternal(v8::String::ExternalStringResource* resource) {
  v8::Isolate* isolate = reinterpret_cast<v8::Isolate*>(i::Isolate::Current());
  return MakeExternal(isolate, resource);
}

bool v8::String::MakeExternal(Isolate* isolate,
                              v8::String::ExternalStringResource* resource) {
  i::DisallowGarbageCollection no_gc;

  i::Tagged<i::String> obj = *Utils::OpenDirectHandle(this);

  if (i::IsThinString(obj)) {
    obj = i::Cast<i::ThinString>(obj)->actual();
  }

  if (!obj->SupportsExternalization(Encoding::TWO_BYTE_ENCODING)) {
    return false;
  }

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);

  CHECK(resource && resource->data());

  bool result = obj->MakeExternal(i_isolate, resource);
  DCHECK_IMPLIES(result, HasExternalStringResource(obj));
  return result;
}

bool v8::String::MakeExternal(
    v8::String::ExternalOneByteStringResource* resource) {
  v8::Isolate* isolate = reinterpret_cast<v8::Isolate*>(i::Isolate::Current());
  return MakeExternal(isolate, resource);
}

bool v8::String::MakeExternal(
    Isolate* isolate, v8::String::ExternalOneByteStringResource* resource) {
  i::DisallowGarbageCollection no_gc;

  i::Tagged<i::String> obj = *Utils::OpenDirectHandle(this);

  if (i::IsThinString(obj)) {
    obj = i::Cast<i::ThinString>(obj)->actual();
  }

  if (!obj->SupportsExternalization(Encoding::ONE_BYTE_ENCODING)) {
    return false;
  }

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);

  CHECK(resource && resource->data());

  bool result = obj->MakeExternal(i_isolate, resource);
  DCHECK_IMPLIES(result, HasExternalStringResource(obj));
  return result;
}

bool v8::String::CanMakeExternal(Encoding encoding) const {
  i::Tagged<i::String> obj = *Utils::OpenDirectHandle(this);

  return obj->SupportsExternalization(encoding);
}

bool v8::String::StringEquals(Local<String> that) const {
  auto self = Utils::OpenDirectHandle(this);
  auto other = Utils::OpenDirectHandle(*that);
  return self->Equals(*other);
}

Isolate* v8::Object::GetIsolate() {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(this)->GetIsolate();
  return reinterpret_cast<Isolate*>(i_isolate);
}

Local<v8::Object> v8::Object::New(Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, Object, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::JSObject> obj =
      i_isolate->factory()->NewJSObject(i_isolate->object_function());
  return Utils::ToLocal(obj);
}

namespace {

// TODO(v8:7569): This is a workaround for the Handle vs MaybeHandle difference
// in the return types of the different Add functions:
// OrderedNameDictionary::Add returns MaybeHandle, NameDictionary::Add returns
// Handle.
template <typename T>
i::Handle<T> ToHandle(i::Handle<T> h) {
  return h;
}
template <typename T>
i::Handle<T> ToHandle(i::MaybeHandle<T> h) {
  return h.ToHandleChecked();
}

#ifdef V8_ENABLE_DIRECT_HANDLE
template <typename T>
i::DirectHandle<T> ToHandle(i::DirectHandle<T> h) {
  return h;
}
template <typename T>
i::DirectHandle<T> ToHandle(i::MaybeDirectHandle<T> h) {
  return h.ToHandleChecked();
}
#endif

template <typename Dictionary>
void AddPropertiesAndElementsToObject(i::Isolate* i_isolate,
                                      i::Handle<Dictionary>& properties,
                                      i::Handle<i::FixedArrayBase>& elements,
                                      Local<Name>* names, Local<Value>* values,
                                      size_t length) {
  for (size_t i = 0; i < length; ++i) {
    auto name = Utils::OpenHandle(*names[i]);
    auto value = Utils::OpenHandle(*values[i]);

    // See if the {name} is a valid array index, in which case we need to
    // add the {name}/{value} pair to the {elements}, otherwise they end
    // up in the {properties} backing store.
    uint32_t index;
    if (name->AsArrayIndex(&index)) {
      // If this is the first element, allocate a proper
      // dictionary elements backing store for {elements}.
      if (!IsNumberDictionary(*elements)) {
        elements =
            i::NumberDictionary::New(i_isolate, static_cast<int>(length));
      }
      elements = i::NumberDictionary::Set(
          i_isolate, i::Cast<i::NumberDictionary>(elements), index, value);
    } else {
      // Internalize the {name} first.
      name = i_isolate->factory()->InternalizeName(name);
      i::InternalIndex const entry = properties->FindEntry(i_isolate, name);
      if (entry.is_not_found()) {
        // Add the {name}/{value} pair as a new entry.
        properties = ToHandle(Dictionary::Add(
            i_isolate, properties, name, value, i::PropertyDetails::Empty()));
      } else {
        // Overwrite the {entry} with the {value}.
        properties->ValueAtPut(entry, *value);
      }
    }
  }
}

}  // namespace

Local<v8::Object> v8::Object::New(Isolate* v8_isolate,
                                  Local<Value> prototype_or_null,
                                  Local<Name>* names, Local<Value>* values,
                                  size_t length) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::Handle<i::JSPrototype> proto;
  if (!Utils::ApiCheck(
          i::TryCast(Utils::OpenHandle(*prototype_or_null), &proto),
          "v8::Object::New", "prototype must be null or object")) {
    return Local<v8::Object>();
  }
  API_RCS_SCOPE(i_isolate, Object, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);

  i::Handle<i::FixedArrayBase> elements =
      i_isolate->factory()->empty_fixed_array();

  // We assume that this API is mostly used to create objects with named
  // properties, and so we default to creating a properties backing store
  // large enough to hold all of them, while we start with no elements
  // (see http://bit.ly/v8-fast-object-create-cpp for the motivation).
  if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    i::Handle<i::SwissNameDictionary> properties =
        i_isolate->factory()->NewSwissNameDictionary(static_cast<int>(length));
    AddPropertiesAndElementsToObject(i_isolate, properties, elements, names,
                                     values, length);
    i::Handle<i::JSObject> obj =
        i_isolate->factory()->NewSlowJSObjectWithPropertiesAndElements(
            proto, properties, elements);
    return Utils::ToLocal(obj);
  } else {
    i::Handle<i::NameDictionary> properties =
        i::NameDictionary::New(i_isolate, static_cast<int>(length));
    AddPropertiesAndElementsToObject(i_isolate, properties, elements, names,
                                     values, length);
    i::Handle<i::JSObject> obj =
        i_isolate->factory()->NewSlowJSObjectWithPropertiesAndElements(
            proto, properties, elements);
    return Utils::ToLocal(obj);
  }
}

Local<v8::Value> v8::NumberObject::New(Isolate* v8_isolate, double value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, NumberObject, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Object> number = i_isolate->factory()->NewNumber(value);
  i::Handle<i::Object> obj =
      i::Object::ToObject(i_isolate, number).ToHandleChecked();
  return Utils::ToLocal(obj);
}

double v8::NumberObject::ValueOf() const {
  auto obj = Utils::OpenDirectHandle(this);
  auto js_primitive_wrapper = i::Cast<i::JSPrimitiveWrapper>(obj);
  API_RCS_SCOPE(js_primitive_wrapper->GetIsolate(), NumberObject, NumberValue);
  return i::Object::NumberValue(
      i::Cast<i::Number>(js_primitive_wrapper->value()));
}

Local<v8::Value> v8::BigIntObject::New(Isolate* v8_isolate, int64_t value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, BigIntObject, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Object> bigint = i::BigInt::FromInt64(i_isolate, value);
  i::Handle<i::Object> obj =
      i::Object::ToObject(i_isolate, bigint).ToHandleChecked();
  return Utils::ToLocal(obj);
}

Local<v8::BigInt> v8::BigIntObject::ValueOf() const {
  auto obj = Utils::OpenHandle(this);
  auto js_primitive_wrapper = i::Cast<i::JSPrimitiveWrapper>(obj);
  i::Isolate* i_isolate = js_primitive_wrapper->GetIsolate();
  API_RCS_SCOPE(i_isolate, BigIntObject, BigIntValue);
  return Utils::ToLocal(i::direct_handle(
      i::Cast<i::BigInt>(js_primitive_wrapper->value()), i_isolate));
}

Local<v8::Value> v8::BooleanObject::New(Isolate* v8_isolate, bool value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, BooleanObject, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Object> boolean =
      i::ReadOnlyRoots(i_isolate).boolean_value_handle(value);
  i::Handle<i::Object> obj =
      i::Object::ToObject(i_isolate, boolean).ToHandleChecked();
  return Utils::ToLocal(obj);
}

bool v8::BooleanObject::ValueOf() const {
  i::Tagged<i::Object> obj = *Utils::OpenDirectHandle(this);
  i::Tagged<i::JSPrimitiveWrapper> js_primitive_wrapper =
      i::Cast<i::JSPrimitiveWrapper>(obj);
  i::Isolate* i_isolate = js_primitive_wrapper->GetIsolate();
  API_RCS_SCOPE(i_isolate, BooleanObject, BooleanValue);
  return i::IsTrue(js_primitive_wrapper->value(), i_isolate);
}

Local<v8::Value> v8::StringObject::New(Isolate* v8_isolate,
                                       Local<String> value) {
  auto string = Utils::OpenHandle(*value);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, StringObject, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Object> obj =
      i::Object::ToObject(i_isolate, string).ToHandleChecked();
  return Utils::ToLocal(obj);
}

Local<v8::String> v8::StringObject::ValueOf() const {
  auto obj = Utils::OpenDirectHandle(this);
  auto js_primitive_wrapper = i::Cast<i::JSPrimitiveWrapper>(obj);
  i::Isolate* i_isolate = js_primitive_wrapper->GetIsolate();
  API_RCS_SCOPE(i_isolate, StringObject, StringValue);
  return Utils::ToLocal(i::direct_handle(
      i::Cast<i::String>(js_primitive_wrapper->value()), i_isolate));
}

Local<v8::Value> v8::SymbolObject::New(Isolate* v8_isolate,
                                       Local<Symbol> value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, SymbolObject, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Object> obj =
      i::Object::ToObject(i_isolate, Utils::OpenHandle(*value))
          .ToHandleChecked();
  return Utils::ToLocal(obj);
}

Local<v8::Symbol> v8::SymbolObject::ValueOf() const {
  auto obj = Utils::OpenDirectHandle(this);
  auto js_primitive_wrapper = i::Cast<i::JSPrimitiveWrapper>(obj);
  i::Isolate* i_isolate = js_primitive_wrapper->GetIsolate();
  API_RCS_SCOPE(i_isolate, SymbolObject, SymbolValue);
  return Utils::ToLocal(i::direct_handle(
      i::Cast<i::Symbol>(js_primitive_wrapper->value()), i_isolate));
}

MaybeLocal<v8::Value> v8::Date::New(Local<Context> context, double time) {
  if (std::isnan(time)) {
    // Introduce only canonical NaN value into the VM, to avoid signaling NaNs.
    time = std::numeric_limits<double>::quiet_NaN();
  }
  PREPARE_FOR_EXECUTION(context, Date, New);
  Local<Value> result;
  has_exception =
      !ToLocal<Value>(i::JSDate::New(i_isolate->date_function(),
                                     i_isolate->date_function(), time),
                      &result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(result);
}

MaybeLocal<Value> v8::Date::Parse(Local<Context> context, Local<String> value) {
  PREPARE_FOR_EXECUTION(context, Date, Parse);
  auto string = Utils::OpenHandle(*value);
  double time = ParseDateTimeString(i_isolate, string);

  Local<Value> result;
  has_exception =
      !ToLocal<Value>(i::JSDate::New(i_isolate->date_function(),
                                     i_isolate->date_function(), time),
                      &result);

  RETURN_ON_FAILED_EXECUTION(Value)
  RETURN_ESCAPED(result);
}

double v8::Date::ValueOf() const {
  auto obj = Utils::OpenDirectHandle(this);
  auto jsdate = i::Cast<i::JSDate>(obj);
  return jsdate->value();
}

v8::Local<v8::String> v8::Date::ToISOString() const {
  auto obj = Utils::OpenDirectHandle(this);
  auto jsdate = i::Cast<i::JSDate>(obj);
  i::Isolate* i_isolate = jsdate->GetIsolate();
  i::DateBuffer buffer =
      i::ToDateString(jsdate->value(), i_isolate->date_cache(),
                      i::ToDateStringMode::kISODateAndTime);
  i::Handle<i::String> str = i_isolate->factory()
                                 ->NewStringFromUtf8(base::VectorOf(buffer))
                                 .ToHandleChecked();
  return Utils::ToLocal(str);
}

v8::Local<v8::String> v8::Date::ToUTCString() const {
  auto obj = Utils::OpenDirectHandle(this);
  auto jsdate = i::Cast<i::JSDate>(obj);
  i::Isolate* i_isolate = jsdate->GetIsolate();
  i::DateBuffer buffer =
      i::ToDateString(jsdate->value(), i_isolate->date_cache(),
                      i::ToDateStringMode::kUTCDateAndTime);
  i::Handle<i::String> str = i_isolate->factory()
                                 ->NewStringFromUtf8(base::VectorOf(buffer))
                                 .ToHandleChecked();
  return Utils::ToLocal(str);
}

// Assert that the static TimeZoneDetection cast in
// DateTimeConfigurationChangeNotification is valid.
#define TIME_ZONE_DETECTION_ASSERT_EQ(value)                     \
  static_assert(                                                 \
      static_cast<int>(v8::Isolate::TimeZoneDetection::value) == \
      static_cast<int>(base::TimezoneCache::TimeZoneDetection::value));
TIME_ZONE_DETECTION_ASSERT_EQ(kSkip)
TIME_ZONE_DETECTION_ASSERT_EQ(kRedetect)
#undef TIME_ZONE_DETECTION_ASSERT_EQ

MaybeLocal<v8::RegExp> v8::RegExp::New(Local<Context> context,
                                       Local<String> pattern, Flags flags) {
  PREPARE_FOR_EXECUTION(context, RegExp, New);
  Local<v8::RegExp> result;
  has_exception =
      !ToLocal<RegExp>(i::JSRegExp::New(i_isolate, Utils::OpenHandle(*pattern),
                                        static_cast<i::JSRegExp::Flags>(flags)),
                       &result);
  RETURN_ON_FAILED_EXECUTION(RegExp);
  RETURN_ESCAPED(result);
}

MaybeLocal<v8::RegExp> v8::RegExp::NewWithBacktrackLimit(
    Local<Context> context, Local<String> pattern, Flags flags,
    uint32_t backtrack_limit) {
  Utils::ApiCheck(i::Smi::IsValid(backtrack_limit),
                  "v8::RegExp::NewWithBacktrackLimit",
                  "backtrack_limit is too large or too small");
  Utils::ApiCheck(backtrack_limit != i::JSRegExp::kNoBacktrackLimit,
                  "v8::RegExp::NewWithBacktrackLimit",
                  "Must set backtrack_limit");
  PREPARE_FOR_EXECUTION(context, RegExp, New);
  Local<v8::RegExp> result;
  has_exception = !ToLocal<RegExp>(
      i::JSRegExp::New(i_isolate, Utils::OpenHandle(*pattern),
                       static_cast<i::JSRegExp::Flags>(flags), backtrack_limit),
      &result);
  RETURN_ON_FAILED_EXECUTION(RegExp);
  RETURN_ESCAPED(result);
}

Local<v8::String> v8::RegExp::GetSource() const {
  auto obj = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = obj->GetIsolate();
  return Utils::ToLocal(i::direct_handle(obj->EscapedPattern(), i_isolate));
}

// Assert that the static flags cast in GetFlags is valid.
#define REGEXP_FLAG_ASSERT_EQ(flag)                   \
  static_assert(static_cast<int>(v8::RegExp::flag) == \
                static_cast<int>(i::JSRegExp::flag))
REGEXP_FLAG_ASSERT_EQ(kNone);
REGEXP_FLAG_ASSERT_EQ(kGlobal);
REGEXP_FLAG_ASSERT_EQ(kIgnoreCase);
REGEXP_FLAG_ASSERT_EQ(kMultiline);
REGEXP_FLAG_ASSERT_EQ(kSticky);
REGEXP_FLAG_ASSERT_EQ(kUnicode);
REGEXP_FLAG_ASSERT_EQ(kHasIndices);
REGEXP_FLAG_ASSERT_EQ(kLinear);
REGEXP_FLAG_ASSERT_EQ(kUnicodeSets);
#undef REGEXP_FLAG_ASSERT_EQ

v8::RegExp::Flags v8::RegExp::GetFlags() const {
  auto obj = Utils::OpenDirectHandle(this);
  return RegExp::Flags(static_cast<int>(obj->flags()));
}

MaybeLocal<v8::Object> v8::RegExp::Exec(Local<Context> context,
                                        Local<v8::String> subject) {
  PREPARE_FOR_EXECUTION(context, RegExp, Exec);

  auto regexp = Utils::OpenHandle(this);
  auto subject_string = Utils::OpenHandle(*subject);

  // TODO(jgruber): RegExpUtils::RegExpExec was not written with efficiency in
  // mind. It fetches the 'exec' property and then calls it through JSEntry.
  // Unfortunately, this is currently the only full implementation of
  // RegExp.prototype.exec available in C++.
  Local<v8::Object> result;
  has_exception = !ToLocal<Object>(
      i::RegExpUtils::RegExpExec(i_isolate, regexp, subject_string,
                                 i_isolate->factory()->undefined_value()),
      &result);

  RETURN_ON_FAILED_EXECUTION(Object);
  RETURN_ESCAPED(result);
}

Local<v8::Ar
"""


```