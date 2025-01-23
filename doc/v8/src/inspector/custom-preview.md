Response: The user wants to understand the functionality of the `custom-preview.cc` file in the V8 inspector. I need to analyze the C++ code and explain its purpose. Specifically, I need to identify if and how it interacts with JavaScript, and provide a JavaScript example if such a connection exists.

**Code Analysis:**

The code defines a mechanism for generating custom previews of JavaScript objects in the V8 inspector. Here's a breakdown of its key functionalities:

1. **Error Reporting:**  The `reportError` functions handle exceptions that occur during the custom preview generation process and log them to the console.

2. **Injected Script Access:** The `getInjectedScript` function retrieves the `InjectedScript` object associated with a given context and session, allowing the C++ code to interact with JavaScript execution contexts.

3. **Object Tag Substitution:** The `substituteObjectTags` function seems to be responsible for processing a JSON-like structure (`jsonML`) representing the preview. It looks for specific tags (like "object") and replaces them with representations of actual JavaScript objects. This is likely used to embed object references within the preview structure.

4. **Body Callback:** The `bodyCallback` function is designed to be called from JavaScript. It takes a configuration object containing the target object and a formatter, and it calls a JavaScript function (`formatter.body`) to generate the detailed preview body. It then processes the result, potentially substituting object tags.

5. **Custom Preview Generation:** The `generateCustomPreview` function is the core of the functionality. It does the following:
    * Retrieves registered formatters from the `devtoolsFormatters` array in the global scope of the JavaScript context.
    * Iterates through these formatters and calls their `header` function (a JavaScript function) to generate the preview header.
    * If a formatter provides a valid header, it checks if the formatter has a `body` function.
    * If a `body` function exists, it creates a callback (`bodyCallback`) to execute this JavaScript function when the user expands the preview in the inspector.
    * It constructs a `CustomPreview` object containing the header and a reference (getter ID) to the body callback.

**JavaScript Interaction:**

The code heavily relies on JavaScript functions defined within the inspected context. The `devtoolsFormatters` array and the `header` and `body` functions within each formatter are JavaScript code that developers provide to customize object previews.

**JavaScript Example:**

I can create a JavaScript example that demonstrates how a developer would define a custom formatter that this C++ code would process.
这个 `custom-preview.cc` 文件是 V8 JavaScript 引擎中用于生成自定义对象预览（Custom Preview）功能的代码。它的主要功能是允许开发者通过 JavaScript 代码自定义在 Chrome DevTools 的检查器（Inspector）中展示特定 JavaScript 对象的方式。

**功能归纳:**

1. **注册和使用自定义格式化器:**  该文件实现了 V8 Inspector 如何查找和调用在 JavaScript 环境中注册的自定义格式化器。开发者可以在全局作用域中定义一个名为 `devtoolsFormatters` 的数组，其中包含描述如何格式化特定对象的对象。

2. **生成预览头部 (Header):**  当需要在 Inspector 中显示一个对象的预览时，V8 会遍历 `devtoolsFormatters` 数组，并调用每个格式化器中定义的 `header` 函数。这个 JavaScript 函数接收被检查的对象和可选的配置作为参数，并返回一个描述预览头部的 JSON-like 的数组结构 (JSONML)。

3. **生成预览主体 (Body，可选):**  格式化器还可以定义一个 `hasBody` 函数来指示是否需要更详细的预览信息。如果需要，并且格式化器提供了 `body` 函数，V8 会在用户展开预览时调用这个函数。 `body` 函数同样接收被检查的对象和可选的配置，并返回一个 JSONML 结构来描述预览主体。

4. **处理 JSONML 结构:**  无论是 `header` 还是 `body` 函数返回的都是一个名为 JSONML 的数组结构，它类似于 HTML 的结构，用于描述预览的内容。`custom-preview.cc` 中的代码会解析和处理这种结构，包括处理其中嵌入的对象引用。

5. **与 Inspector 通信:**  该文件生成的自定义预览信息最终会被传递给 Chrome DevTools 的 Inspector 前端进行展示。

**与 JavaScript 的关系及示例:**

该文件与 JavaScript 的功能紧密相关。开发者通过编写特定的 JavaScript 代码来定义自定义预览的格式，而 `custom-preview.cc` 负责在 V8 引擎层面执行这些 JavaScript 代码并生成最终的预览信息。

**JavaScript 示例:**

假设我们想为 `Person` 类的实例定义一个自定义预览。我们可以在 JavaScript 代码中添加如下的格式化器：

```javascript
if (typeof devtoolsFormatters === 'undefined') {
  devtoolsFormatters = [];
}

devtoolsFormatters.push({
  header: function(obj) {
    if (obj instanceof Person) {
      return ["div", {},
              ["span", { style: "font-weight: bold;" }, "Person: "],
              obj.name + " (" + obj.age + ")"
             ];
    }
    return null; // 表示这个格式化器不适用于当前对象
  },
  hasBody: function(obj) {
    return obj instanceof Person;
  },
  body: function(obj) {
    return ["div", {},
            ["p", {}, "Name: " + obj.name],
            ["p", {}, "Age: " + obj.age],
            ["p", {}, "City: " + obj.city]
           ];
  }
});

class Person {
  constructor(name, age, city) {
    this.name = name;
    this.age = age;
    this.city = city;
  }
}

const person = new Person("Alice", 30, "New York");
console.log(person); // 在 Chrome DevTools 的控制台中查看预览
```

**解释:**

* **`devtoolsFormatters` 数组:** 我们首先检查 `devtoolsFormatters` 是否存在，如果不存在则创建一个空数组。这是 V8 Inspector 查找自定义格式化器的地方。
* **`header` 函数:** 这个函数接收一个对象 `obj` 作为参数。我们检查 `obj` 是否是 `Person` 类的实例。如果是，我们返回一个 JSONML 结构，描述了预览的头部，显示加粗的 "Person: " 标签以及姓名和年龄。如果 `obj` 不是 `Person` 的实例，我们返回 `null`，表示这个格式化器不适用于该对象。
* **`hasBody` 函数:** 这个函数也接收一个对象 `obj`。我们返回 `true` 如果 `obj` 是 `Person` 的实例，表示我们希望提供更详细的预览信息。
* **`body` 函数:** 当用户在 Inspector 中展开 `Person` 对象的预览时，这个函数会被调用。它返回一个包含姓名、年龄和城市的 JSONML 结构，作为预览的主体内容。
* **`Person` 类和实例:**  我们定义了一个简单的 `Person` 类并创建了一个实例 `person`。
* **`console.log(person)`:** 当我们在 Chrome DevTools 的控制台中记录 `person` 对象时，V8 Inspector 会使用我们定义的自定义格式化器来展示预览信息。

**JSONML 结构示例:**

在上面的 JavaScript 示例中，`header` 函数返回的 JSONML 结构如下：

```json
["div", {},
  ["span", { "style": "font-weight: bold;" }, "Person: "],
  "Alice (30)"
]
```

这会被 `custom-preview.cc` 解析并转换为 Inspector 可以理解的 UI 元素，最终在控制台中呈现出更易读的对象预览信息。

总而言之，`custom-preview.cc` 是 V8 Inspector 中实现自定义对象预览的关键 C++ 代码，它通过执行开发者提供的 JavaScript 代码来动态生成对象的预览信息，从而增强了调试体验。

### 提示词
```
这是目录为v8/src/inspector/custom-preview.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/inspector/custom-preview.h"

#include "../../third_party/inspector_protocol/crdtp/json.h"
#include "include/v8-container.h"
#include "include/v8-context.h"
#include "include/v8-function.h"
#include "include/v8-json.h"
#include "include/v8-microtask-queue.h"
#include "src/debug/debug-interface.h"
#include "src/inspector/injected-script.h"
#include "src/inspector/inspected-context.h"
#include "src/inspector/string-util.h"
#include "src/inspector/v8-console-message.h"
#include "src/inspector/v8-debugger.h"
#include "src/inspector/v8-inspector-impl.h"
#include "src/inspector/v8-stack-trace-impl.h"

namespace v8_inspector {

using protocol::Runtime::CustomPreview;

namespace {
void reportError(v8::Local<v8::Context> context, const v8::TryCatch& tryCatch) {
  DCHECK(tryCatch.HasCaught());
  v8::Isolate* isolate = context->GetIsolate();
  V8InspectorImpl* inspector =
      static_cast<V8InspectorImpl*>(v8::debug::GetInspector(isolate));
  int contextId = InspectedContext::contextId(context);
  int groupId = inspector->contextGroupId(contextId);
  v8::Local<v8::String> message = toV8String(isolate, "<no message available>");
  if (!tryCatch.Message().IsEmpty()) message = tryCatch.Message()->Get();
  v8::Local<v8::String> prefix =
      toV8String(isolate, "Custom Formatter Failed: ");
  message = v8::String::Concat(isolate, prefix, message);
  v8::LocalVector<v8::Value> arguments(isolate);
  arguments.push_back(message);
  V8ConsoleMessageStorage* storage =
      inspector->ensureConsoleMessageStorage(groupId);
  if (!storage) return;
  storage->addMessage(V8ConsoleMessage::createForConsoleAPI(
      context, contextId, groupId, inspector,
      inspector->client()->currentTimeMS(), ConsoleAPIType::kError,
      {arguments.begin(), arguments.end()}, String16(), nullptr));
}

void reportError(v8::Local<v8::Context> context, const v8::TryCatch& tryCatch,
                 const String16& message) {
  v8::Isolate* isolate = context->GetIsolate();
  isolate->ThrowException(toV8String(isolate, message));
  reportError(context, tryCatch);
}

InjectedScript* getInjectedScript(v8::Local<v8::Context> context,
                                  int sessionId) {
  v8::Isolate* isolate = context->GetIsolate();
  V8InspectorImpl* inspector =
      static_cast<V8InspectorImpl*>(v8::debug::GetInspector(isolate));
  InspectedContext* inspectedContext =
      inspector->getContext(InspectedContext::contextId(context));
  if (!inspectedContext) return nullptr;
  return inspectedContext->getInjectedScript(sessionId);
}

bool substituteObjectTags(int sessionId, const String16& groupName,
                          v8::Local<v8::Context> context,
                          v8::Local<v8::Array> jsonML, int maxDepth) {
  if (!jsonML->Length()) return true;
  v8::Isolate* isolate = context->GetIsolate();
  v8::TryCatch tryCatch(isolate);

  if (maxDepth <= 0) {
    reportError(context, tryCatch,
                "Too deep hierarchy of inlined custom previews");
    return false;
  }

  v8::Local<v8::Value> firstValue;
  if (!jsonML->Get(context, 0).ToLocal(&firstValue)) {
    reportError(context, tryCatch);
    return false;
  }
  v8::Local<v8::String> objectLiteral = toV8String(isolate, "object");
  if (jsonML->Length() == 2 && firstValue->IsString() &&
      firstValue.As<v8::String>()->StringEquals(objectLiteral)) {
    v8::Local<v8::Value> attributesValue;
    if (!jsonML->Get(context, 1).ToLocal(&attributesValue)) {
      reportError(context, tryCatch);
      return false;
    }
    if (!attributesValue->IsObject()) {
      reportError(context, tryCatch, "attributes should be an Object");
      return false;
    }
    v8::Local<v8::Object> attributes = attributesValue.As<v8::Object>();
    v8::Local<v8::Value> originValue;
    if (!attributes->Get(context, objectLiteral).ToLocal(&originValue)) {
      reportError(context, tryCatch);
      return false;
    }
    if (originValue->IsUndefined()) {
      reportError(context, tryCatch,
                  "obligatory attribute \"object\" isn't specified");
      return false;
    }

    v8::Local<v8::Value> configValue;
    if (!attributes->Get(context, toV8String(isolate, "config"))
             .ToLocal(&configValue)) {
      reportError(context, tryCatch);
      return false;
    }

    InjectedScript* injectedScript = getInjectedScript(context, sessionId);
    if (!injectedScript) {
      reportError(context, tryCatch, "cannot find context with specified id");
      return false;
    }
    std::unique_ptr<protocol::Runtime::RemoteObject> wrapper;
    protocol::Response response = injectedScript->wrapObject(
        originValue, groupName, WrapOptions({WrapMode::kIdOnly}), configValue,
        maxDepth - 1, &wrapper);
    if (!response.IsSuccess() || !wrapper) {
      reportError(context, tryCatch, "cannot wrap value");
      return false;
    }
    std::vector<uint8_t> json;
    v8_crdtp::json::ConvertCBORToJSON(v8_crdtp::SpanFrom(wrapper->Serialize()),
                                      &json);
    v8::Local<v8::Value> jsonWrapper;
    v8_inspector::StringView serialized(json.data(), json.size());
    if (!v8::JSON::Parse(context, toV8String(isolate, serialized))
             .ToLocal(&jsonWrapper)) {
      reportError(context, tryCatch, "cannot wrap value");
      return false;
    }
    if (jsonML->Set(context, 1, jsonWrapper).IsNothing()) {
      reportError(context, tryCatch);
      return false;
    }
  } else {
    for (uint32_t i = 0; i < jsonML->Length(); ++i) {
      v8::Local<v8::Value> value;
      if (!jsonML->Get(context, i).ToLocal(&value)) {
        reportError(context, tryCatch);
        return false;
      }
      if (value->IsArray() && value.As<v8::Array>()->Length() > 0 &&
          !substituteObjectTags(sessionId, groupName, context,
                                value.As<v8::Array>(), maxDepth - 1)) {
        return false;
      }
    }
  }
  return true;
}

void bodyCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  v8::TryCatch tryCatch(isolate);
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Object> bodyConfig = info.Data().As<v8::Object>();

  v8::Local<v8::Value> objectValue;
  if (!bodyConfig->Get(context, toV8String(isolate, "object"))
           .ToLocal(&objectValue)) {
    reportError(context, tryCatch);
    return;
  }
  if (!objectValue->IsObject()) {
    reportError(context, tryCatch, "object should be an Object");
    return;
  }
  v8::Local<v8::Object> object = objectValue.As<v8::Object>();

  v8::Local<v8::Value> formatterValue;
  if (!bodyConfig->Get(context, toV8String(isolate, "formatter"))
           .ToLocal(&formatterValue)) {
    reportError(context, tryCatch);
    return;
  }
  if (!formatterValue->IsObject()) {
    reportError(context, tryCatch, "formatter should be an Object");
    return;
  }
  v8::Local<v8::Object> formatter = formatterValue.As<v8::Object>();

  v8::Local<v8::Value> bodyValue;
  if (!formatter->Get(context, toV8String(isolate, "body"))
           .ToLocal(&bodyValue)) {
    reportError(context, tryCatch);
    return;
  }
  if (!bodyValue->IsFunction()) {
    reportError(context, tryCatch, "body should be a Function");
    return;
  }
  v8::Local<v8::Function> bodyFunction = bodyValue.As<v8::Function>();

  v8::Local<v8::Value> configValue;
  if (!bodyConfig->Get(context, toV8String(isolate, "config"))
           .ToLocal(&configValue)) {
    reportError(context, tryCatch);
    return;
  }

  v8::Local<v8::Value> sessionIdValue;
  if (!bodyConfig->Get(context, toV8String(isolate, "sessionId"))
           .ToLocal(&sessionIdValue)) {
    reportError(context, tryCatch);
    return;
  }
  if (!sessionIdValue->IsInt32()) {
    reportError(context, tryCatch, "sessionId should be an Int32");
    return;
  }

  v8::Local<v8::Value> groupNameValue;
  if (!bodyConfig->Get(context, toV8String(isolate, "groupName"))
           .ToLocal(&groupNameValue)) {
    reportError(context, tryCatch);
    return;
  }
  if (!groupNameValue->IsString()) {
    reportError(context, tryCatch, "groupName should be a string");
    return;
  }

  v8::Local<v8::Value> formattedValue;
  v8::Local<v8::Value> args[] = {object, configValue};
  if (!bodyFunction->Call(context, formatter, 2, args)
           .ToLocal(&formattedValue)) {
    reportError(context, tryCatch);
    return;
  }
  if (formattedValue->IsNull()) {
    info.GetReturnValue().Set(formattedValue);
    return;
  }
  if (!formattedValue->IsArray()) {
    reportError(context, tryCatch, "body should return an Array");
    return;
  }
  v8::Local<v8::Array> jsonML = formattedValue.As<v8::Array>();
  if (jsonML->Length() &&
      !substituteObjectTags(
          sessionIdValue.As<v8::Int32>()->Value(),
          toProtocolString(isolate, groupNameValue.As<v8::String>()), context,
          jsonML, kMaxCustomPreviewDepth)) {
    return;
  }
  info.GetReturnValue().Set(jsonML);
}
}  // anonymous namespace

void generateCustomPreview(v8::Isolate* isolate, int sessionId,
                           const String16& groupName,
                           v8::Local<v8::Object> object,
                           v8::MaybeLocal<v8::Value> maybeConfig, int maxDepth,
                           std::unique_ptr<CustomPreview>* preview) {
  v8::Local<v8::Context> context;
  if (!object->GetCreationContext(isolate).ToLocal(&context)) {
    return;
  }

  v8::MicrotasksScope microtasksScope(context,
                                      v8::MicrotasksScope::kDoNotRunMicrotasks);
  v8::TryCatch tryCatch(isolate);

  v8::Local<v8::Value> configValue;
  if (!maybeConfig.ToLocal(&configValue)) configValue = v8::Undefined(isolate);

  v8::Local<v8::Object> global = context->Global();
  v8::Local<v8::Value> formattersValue;
  if (!global->Get(context, toV8String(isolate, "devtoolsFormatters"))
           .ToLocal(&formattersValue)) {
    reportError(context, tryCatch);
    return;
  }
  if (!formattersValue->IsArray()) return;
  v8::Local<v8::Array> formatters = formattersValue.As<v8::Array>();
  v8::Local<v8::String> headerLiteral = toV8String(isolate, "header");
  v8::Local<v8::String> hasBodyLiteral = toV8String(isolate, "hasBody");
  for (uint32_t i = 0; i < formatters->Length(); ++i) {
    v8::Local<v8::Value> formatterValue;
    if (!formatters->Get(context, i).ToLocal(&formatterValue)) {
      reportError(context, tryCatch);
      return;
    }
    if (!formatterValue->IsObject()) {
      reportError(context, tryCatch, "formatter should be an Object");
      return;
    }
    v8::Local<v8::Object> formatter = formatterValue.As<v8::Object>();

    v8::Local<v8::Value> headerValue;
    if (!formatter->Get(context, headerLiteral).ToLocal(&headerValue)) {
      reportError(context, tryCatch);
      return;
    }
    if (!headerValue->IsFunction()) {
      reportError(context, tryCatch, "header should be a Function");
      return;
    }
    v8::Local<v8::Function> headerFunction = headerValue.As<v8::Function>();

    v8::Local<v8::Value> formattedValue;
    v8::Local<v8::Value> args[] = {object, configValue};
    if (!headerFunction->Call(context, formatter, 2, args)
             .ToLocal(&formattedValue)) {
      reportError(context, tryCatch);
      return;
    }
    if (!formattedValue->IsArray()) continue;
    v8::Local<v8::Array> jsonML = formattedValue.As<v8::Array>();

    v8::Local<v8::Value> hasBodyFunctionValue;
    if (!formatter->Get(context, hasBodyLiteral)
             .ToLocal(&hasBodyFunctionValue)) {
      reportError(context, tryCatch);
      return;
    }
    if (!hasBodyFunctionValue->IsFunction()) continue;
    v8::Local<v8::Function> hasBodyFunction =
        hasBodyFunctionValue.As<v8::Function>();
    v8::Local<v8::Value> hasBodyValue;
    if (!hasBodyFunction->Call(context, formatter, 2, args)
             .ToLocal(&hasBodyValue)) {
      reportError(context, tryCatch);
      return;
    }
    bool hasBody = hasBodyValue->ToBoolean(isolate)->Value();

    if (jsonML->Length() && !substituteObjectTags(sessionId, groupName, context,
                                                  jsonML, maxDepth)) {
      return;
    }

    v8::Local<v8::String> header;
    if (!v8::JSON::Stringify(context, jsonML).ToLocal(&header)) {
      reportError(context, tryCatch);
      return;
    }

    v8::Local<v8::Function> bodyFunction;
    if (hasBody) {
      v8::Local<v8::Object> bodyConfig = v8::Object::New(isolate);
      if (bodyConfig
              ->CreateDataProperty(context, toV8String(isolate, "sessionId"),
                                   v8::Integer::New(isolate, sessionId))
              .IsNothing()) {
        reportError(context, tryCatch);
        return;
      }
      if (bodyConfig
              ->CreateDataProperty(context, toV8String(isolate, "formatter"),
                                   formatter)
              .IsNothing()) {
        reportError(context, tryCatch);
        return;
      }
      if (bodyConfig
              ->CreateDataProperty(context, toV8String(isolate, "groupName"),
                                   toV8String(isolate, groupName))
              .IsNothing()) {
        reportError(context, tryCatch);
        return;
      }
      if (bodyConfig
              ->CreateDataProperty(context, toV8String(isolate, "config"),
                                   configValue)
              .IsNothing()) {
        reportError(context, tryCatch);
        return;
      }
      if (bodyConfig
              ->CreateDataProperty(context, toV8String(isolate, "object"),
                                   object)
              .IsNothing()) {
        reportError(context, tryCatch);
        return;
      }
      if (!v8::Function::New(context, bodyCallback, bodyConfig)
               .ToLocal(&bodyFunction)) {
        reportError(context, tryCatch);
        return;
      }
    }
    *preview = CustomPreview::create()
                   .setHeader(toProtocolString(isolate, header))
                   .build();
    if (!bodyFunction.IsEmpty()) {
      InjectedScript* injectedScript = getInjectedScript(context, sessionId);
      if (!injectedScript) {
        reportError(context, tryCatch, "cannot find context with specified id");
        return;
      }
      (*preview)->setBodyGetterId(
          injectedScript->bindObject(bodyFunction, groupName));
    }
    return;
  }
}
}  // namespace v8_inspector
```