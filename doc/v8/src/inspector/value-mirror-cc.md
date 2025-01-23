Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/inspector/value-mirror.cc`. I need to:

1. **Identify the primary purpose of the code.**  Based on the file name and the code content, it seems to be related to converting V8 JavaScript values into a format suitable for the DevTools protocol.

2. **Check if it's Torque code.**  The filename ends with `.cc`, not `.tq`.

3. **Explain its relationship to JavaScript.** This code handles the conversion of various JavaScript data types. I should provide JavaScript examples of these types.

4. **Look for code logic and provide an example with input and output.** The `toProtocolValue` functions appear to be central to the conversion logic. I can illustrate how a JavaScript value is processed.

5. **Identify potential user programming errors.**  Issues might arise when dealing with large object graphs or unserializable values.

6. **Summarize the functionality.**  Combine the above points into a concise summary.
好的，根据你提供的代码，`v8/src/inspector/value-mirror.cc` 的主要功能是：

**功能归纳：**

`v8/src/inspector/value-mirror.cc` 负责将 V8 引擎内部的 JavaScript 值转换为 DevTools 协议（Chrome DevTools 使用的通信协议）中定义的 `protocol::Runtime::RemoteObject` 或 `protocol::Value` 等数据结构。这使得开发者工具能够检查和显示 JavaScript 运行时环境中的变量、对象和其他值。

**详细功能点：**

1. **数据类型转换：**  代码中包含多个 `toProtocolValue` 函数，这些函数针对不同的 V8 数据类型（例如 `v8::Value`, `v8::Array`, `v8::Object`, `v8::String`, `v8::Number`, `v8::Boolean`, `v8::Symbol`, `v8::BigInt` 等）进行转换，将其转换为 DevTools 协议中相应的表示。

2. **对象和数组的递归处理：**  对于对象和数组，转换过程是递归的，会遍历其属性和元素，并将它们也转换为协议规定的格式。`maxDepth` 参数用于控制递归深度，防止因循环引用或过深的对象结构导致无限递归。

3. **基本类型的直接转换：**  对于基本类型（null, undefined, boolean, number, string），会直接创建相应的 `protocol::FundamentalValue` 或 `protocol::StringValue`。

4. **特殊对象的处理：** 代码中包含对一些特殊 JavaScript 对象的处理，例如：
   - **Error 对象：**  会提取 `name`、`message` 和 `stack` 属性来生成描述信息。
   - **Symbol 对象：**  会提取其描述信息。
   - **BigInt 对象：**  会将其转换为字符串表示。
   - **RegExp 对象：**  会提取其模式和标志。
   - **Date 对象：**  会获取其字符串表示。
   - **Proxy 对象：** 会尝试获取其目标对象的描述。
   - **Map 和 Set 等集合对象：**  会显示其大小。
   - **Function 对象：** 会获取其描述信息。

5. **生成预览信息 (`ObjectPreview`, `PropertyPreview`, `EntryPreview`)：** 除了完整的 `RemoteObject`，代码还生成用于在开发者工具中显示简洁预览信息的结构。这些预览信息通常用于概览对象或数组的内容。

6. **深度序列化：** 实现了 `buildDeepSerializedValue` 函数，用于更深层次的序列化，可以处理循环引用，并将结果存储在 `protocol::DictionaryValue` 中。

**关于代码特性的回答：**

* **是否为 Torque 代码:**  `v8/src/inspector/value-mirror.cc` 的文件名以 `.cc` 结尾，所以它不是 V8 Torque 源代码。Torque 源代码的文件名以 `.tq` 结尾。

* **与 JavaScript 功能的关系及示例:**  这个 C++ 代码直接服务于 JavaScript 的调试和检查。它负责将 JavaScript 的运行时值传递给开发者工具。

   ```javascript
   // JavaScript 示例

   const myObject = {
       name: "示例对象",
       value: 123,
       nested: {
           a: true
       },
       method: function() {
           console.log("Hello");
       }
   };

   const myArray = [1, "two", myObject];

   const myError = new Error("Something went wrong");
   ```

   当开发者工具连接到 V8 引擎并尝试检查 `myObject`、`myArray` 或 `myError` 时，`v8/src/inspector/value-mirror.cc` 中的代码会被调用，将这些 JavaScript 值转换为开发者工具可以理解的协议格式，例如：

   ```json
   // 可能的 RemoteObject 表示 (简化)
   {
       "type": "object",
       "className": "Object",
       "description": "Object",
       "objectId": "someObjectId", // 唯一标识符
       "preview": {
           "type": "object",
           "description": "Object",
           "overflow": false,
           "properties": [
               { "name": "name", "type": "string", "value": "\"示例对象\"" },
               { "name": "value", "type": "number", "value": "123" },
               { "name": "nested", "type": "object", "value": "Object" },
               { "name": "method", "type": "function", "value": "function()" }
           ]
       }
   }
   ```

* **代码逻辑推理示例：**

   **假设输入 (JavaScript):**

   ```javascript
   const data = {
       a: 10,
       b: "hello"
   };
   ```

   当调试器尝试获取 `data` 的值时，`objectToProtocolValue` 函数会被调用。

   **假设 `maxDepth` 为 1。**

   1. `object->GetOwnPropertyNames(context)` 会获取属性名：`["a", "b"]`。
   2. 遍历属性名：
      - 对于 "a":
         - 获取属性值 `10`。
         - 调用 `toProtocolValue` 处理数字 `10`，生成 `protocol::FundamentalValue::create(10)`。
         - 将 `"a": 10` 添加到 `jsonObject`。
      - 对于 "b":
         - 获取属性值 `"hello"`。
         - 调用 `toProtocolValue` 处理字符串 `"hello"`，生成 `protocol::StringValue::create("hello")`。
         - 将 `"b": "hello"` 添加到 `jsonObject`。

   **预期输出 (protocol::DictionaryValue):**

   ```json
   {
       "a": 10,
       "b": "hello"
   }
   ```

* **用户常见的编程错误:**

   - **循环引用导致堆栈溢出:** 如果 JavaScript 对象之间存在循环引用（例如 `a.b = c; c.d = a;`），并且调试器尝试深层遍历这个对象，可能会因为递归过深而导致堆栈溢出。`maxDepth` 参数在一定程度上可以缓解这个问题。

   - **访问不存在的属性导致错误:** 虽然代码中使用了 `Get` 方法，但通常 V8 的 API 会处理这种情况，返回 `undefined` 而不是抛出错误。然而，如果用户在 getter 中编写了可能抛出异常的代码，那么在调试器尝试获取属性值时可能会遇到问题。

   - **尝试序列化不可序列化的值:** 某些 JavaScript 值，如 WeakMap 或 WeakSet，本质上是不可序列化的。`value-mirror.cc` 中的代码会尝试将它们转换为合适的 DevTools 协议表示，但可能无法提供所有信息。

   - **在代理对象中使用拦截器导致意外行为:** 代码中提到 "Don't access properties with interceptors."，这意味着如果一个对象使用了 Proxy 并且定义了拦截器，调试器在尝试获取属性时可能会触发拦截器中的代码，这可能会导致用户意想不到的副作用或性能问题。

总而言之，`v8/src/inspector/value-mirror.cc` 是 V8 调试基础设施的关键组成部分，它使得开发者工具能够理解和展示 JavaScript 代码的运行时状态。

### 提示词
```
这是目录为v8/src/inspector/value-mirror.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/value-mirror.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/inspector/value-mirror.h"

#include <algorithm>
#include <cmath>
#include <optional>

#include "include/v8-container.h"
#include "include/v8-date.h"
#include "include/v8-function.h"
#include "include/v8-microtask-queue.h"
#include "include/v8-primitive-object.h"
#include "include/v8-proxy.h"
#include "include/v8-regexp.h"
#include "include/v8-typed-array.h"
#include "include/v8-wasm.h"
#include "src/debug/debug-interface.h"
#include "src/inspector/v8-debugger.h"
#include "src/inspector/v8-deep-serializer.h"
#include "src/inspector/v8-inspector-impl.h"
#include "src/inspector/v8-serialization-duplicate-tracker.h"

namespace v8_inspector {

using protocol::Response;
using protocol::Runtime::EntryPreview;
using protocol::Runtime::ObjectPreview;
using protocol::Runtime::PropertyPreview;
using protocol::Runtime::RemoteObject;

#if defined(V8_USE_ADDRESS_SANITIZER) && V8_OS_DARWIN
// For whatever reason, ASan on MacOS has bigger stack frames.
static const int kMaxProtocolDepth = 900;
#else
static const int kMaxProtocolDepth = 1000;
#endif

Response toProtocolValue(v8::Local<v8::Context> context,
                         v8::Local<v8::Value> value, int maxDepth,
                         std::unique_ptr<protocol::Value>* result);

Response arrayToProtocolValue(v8::Local<v8::Context> context,
                              v8::Local<v8::Array> array, int maxDepth,
                              std::unique_ptr<protocol::ListValue>* result) {
  std::unique_ptr<protocol::ListValue> inspectorArray =
      protocol::ListValue::create();
  uint32_t length = array->Length();
  for (uint32_t i = 0; i < length; i++) {
    v8::Local<v8::Value> value;
    if (!array->Get(context, i).ToLocal(&value))
      return Response::InternalError();
    std::unique_ptr<protocol::Value> element;
    Response response = toProtocolValue(context, value, maxDepth - 1, &element);
    if (!response.IsSuccess()) return response;
    inspectorArray->pushValue(std::move(element));
  }
  *result = std::move(inspectorArray);
  return Response::Success();
}

Response objectToProtocolValue(
    v8::Local<v8::Context> context, v8::Local<v8::Object> object, int maxDepth,
    std::unique_ptr<protocol::DictionaryValue>* result) {
  std::unique_ptr<protocol::DictionaryValue> jsonObject =
      protocol::DictionaryValue::create();
  v8::Local<v8::Array> propertyNames;
  if (!object->GetOwnPropertyNames(context).ToLocal(&propertyNames))
    return Response::InternalError();
  uint32_t length = propertyNames->Length();
  for (uint32_t i = 0; i < length; i++) {
    v8::Local<v8::Value> name;
    if (!propertyNames->Get(context, i).ToLocal(&name))
      return Response::InternalError();
    if (name->IsString()) {
      v8::Maybe<bool> hasRealNamedProperty =
          object->HasRealNamedProperty(context, name.As<v8::String>());
      // Don't access properties with interceptors.
      if (hasRealNamedProperty.IsNothing() || !hasRealNamedProperty.FromJust())
        continue;
    }
    v8::Local<v8::String> propertyName;
    if (!name->ToString(context).ToLocal(&propertyName)) continue;
    v8::Local<v8::Value> property;
    if (!object->Get(context, name).ToLocal(&property))
      return Response::InternalError();
    if (property->IsUndefined()) continue;
    std::unique_ptr<protocol::Value> propertyValue;
    Response response =
        toProtocolValue(context, property, maxDepth - 1, &propertyValue);
    if (!response.IsSuccess()) return response;
    jsonObject->setValue(toProtocolString(context->GetIsolate(), propertyName),
                         std::move(propertyValue));
  }
  *result = std::move(jsonObject);
  return Response::Success();
}

std::unique_ptr<protocol::FundamentalValue> toProtocolValue(
    double doubleValue) {
  if (doubleValue >= std::numeric_limits<int>::min() &&
      doubleValue <= std::numeric_limits<int>::max() &&
      v8::base::bit_cast<int64_t>(doubleValue) !=
          v8::base::bit_cast<int64_t>(-0.0)) {
    int intValue = static_cast<int>(doubleValue);
    if (intValue == doubleValue) {
      return protocol::FundamentalValue::create(intValue);
    }
  }
  return protocol::FundamentalValue::create(doubleValue);
}

Response toProtocolValue(v8::Local<v8::Context> context,
                         v8::Local<v8::Value> value, int maxDepth,
                         std::unique_ptr<protocol::Value>* result) {
  if (maxDepth <= 0)
    return Response::ServerError("Object reference chain is too long");

  if (value->IsNull() || value->IsUndefined()) {
    *result = protocol::Value::null();
    return Response::Success();
  }
  if (value->IsBoolean()) {
    *result =
        protocol::FundamentalValue::create(value.As<v8::Boolean>()->Value());
    return Response::Success();
  }
  if (value->IsNumber()) {
    double doubleValue = value.As<v8::Number>()->Value();
    *result = toProtocolValue(doubleValue);
    return Response::Success();
  }
  if (value->IsString()) {
    *result = protocol::StringValue::create(
        toProtocolString(context->GetIsolate(), value.As<v8::String>()));
    return Response::Success();
  }
  if (value->IsArray()) {
    v8::Local<v8::Array> array = value.As<v8::Array>();
    std::unique_ptr<protocol::ListValue> list_result;
    auto response =
        arrayToProtocolValue(context, array, maxDepth, &list_result);
    *result = std::move(list_result);
    return response;
  }
  if (value->IsObject()) {
    v8::Local<v8::Object> object = value.As<v8::Object>();
    std::unique_ptr<protocol::DictionaryValue> dict_result;
    auto response =
        objectToProtocolValue(context, object, maxDepth, &dict_result);
    *result = std::move(dict_result);
    return response;
  }

  return Response::ServerError("Object couldn't be returned by value");
}

Response toProtocolValue(v8::Local<v8::Context> context,
                         v8::Local<v8::Value> value,
                         std::unique_ptr<protocol::Value>* result) {
  if (value->IsUndefined()) return Response::Success();
  return toProtocolValue(context, value, kMaxProtocolDepth, result);
}

namespace {

// WebAssembly memory is organized in pages of size 64KiB.
const size_t kWasmPageSize = 64 * 1024;

V8InspectorClient* clientFor(v8::Local<v8::Context> context) {
  return static_cast<V8InspectorImpl*>(
             v8::debug::GetInspector(context->GetIsolate()))
      ->client();
}

V8InternalValueType v8InternalValueTypeFrom(v8::Local<v8::Context> context,
                                            v8::Local<v8::Value> value) {
  if (!value->IsObject()) return V8InternalValueType::kNone;
  V8InspectorImpl* inspector = static_cast<V8InspectorImpl*>(
      v8::debug::GetInspector(context->GetIsolate()));
  int contextId = InspectedContext::contextId(context);
  InspectedContext* inspectedContext = inspector->getContext(contextId);
  if (!inspectedContext) return V8InternalValueType::kNone;
  return inspectedContext->getInternalType(value.As<v8::Object>());
}

enum AbbreviateMode { kMiddle, kEnd };

String16 abbreviateString(const String16& value, AbbreviateMode mode) {
  const size_t maxLength = 100;
  if (value.length() <= maxLength) return value;
  UChar ellipsis = static_cast<UChar>(0x2026);
  if (mode == kMiddle) {
    return String16::concat(
        value.substring(0, maxLength / 2), String16(&ellipsis, 1),
        value.substring(value.length() - maxLength / 2 + 1));
  }
  return String16::concat(value.substring(0, maxLength - 1), ellipsis);
}

String16 descriptionForSymbol(v8::Local<v8::Context> context,
                              v8::Local<v8::Symbol> symbol) {
  v8::Isolate* isolate = context->GetIsolate();
  return String16::concat(
      "Symbol(",
      toProtocolStringWithTypeCheck(isolate, symbol->Description(isolate)),
      ")");
}

String16 descriptionForBigInt(v8::Local<v8::Context> context,
                              v8::Local<v8::BigInt> value) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::Local<v8::String> description =
      v8::debug::GetBigIntDescription(isolate, value);
  return toProtocolString(isolate, description);
}

String16 descriptionForPrimitiveType(v8::Local<v8::Context> context,
                                     v8::Local<v8::Value> value) {
  if (value->IsUndefined()) return RemoteObject::TypeEnum::Undefined;
  if (value->IsNull()) return RemoteObject::SubtypeEnum::Null;
  if (value->IsBoolean()) {
    return value.As<v8::Boolean>()->Value() ? "true" : "false";
  }
  if (value->IsString()) {
    return toProtocolString(context->GetIsolate(), value.As<v8::String>());
  }
  UNREACHABLE();
}

String16 descriptionForRegExp(v8::Isolate* isolate,
                              v8::Local<v8::RegExp> value) {
  String16Builder description;
  description.append('/');
  description.append(toProtocolString(isolate, value->GetSource()));
  description.append('/');
  v8::RegExp::Flags flags = value->GetFlags();
  if (flags & v8::RegExp::Flags::kHasIndices) description.append('d');
  if (flags & v8::RegExp::Flags::kGlobal) description.append('g');
  if (flags & v8::RegExp::Flags::kIgnoreCase) description.append('i');
  if (flags & v8::RegExp::Flags::kLinear) description.append('l');
  if (flags & v8::RegExp::Flags::kMultiline) description.append('m');
  if (flags & v8::RegExp::Flags::kDotAll) description.append('s');
  if (flags & v8::RegExp::Flags::kUnicode) description.append('u');
  if (flags & v8::RegExp::Flags::kUnicodeSets) description.append('v');
  if (flags & v8::RegExp::Flags::kSticky) description.append('y');
  return description.toString();
}

// Build a description from an exception using the following pattern:
//   * The first line is "<name || constructor name>: <message property>". We
//     use the constructor name if the "name" property is "Error". Most custom
//     Error subclasses don't overwrite the "name" property.
//   * The rest is the content of the "stack" property but only with the actual
//     stack trace part.
String16 descriptionForError(v8::Local<v8::Context> context,
                             v8::Local<v8::Object> object) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::TryCatch tryCatch(isolate);

  String16 name = toProtocolString(isolate, object->GetConstructorName());
  {
    v8::Local<v8::Value> nameValue;
    if (object->Get(context, toV8String(isolate, "name")).ToLocal(&nameValue) &&
        nameValue->IsString()) {
      v8::Local<v8::String> nameString = nameValue.As<v8::String>();
      if (nameString->Length() > 0 &&
          !nameString->StringEquals(toV8String(isolate, "Error"))) {
        name = toProtocolString(isolate, nameString);
      }
    }
  }

  std::optional<String16> stack;
  {
    v8::Local<v8::Value> stackValue;
    if (object->Get(context, toV8String(isolate, "stack"))
            .ToLocal(&stackValue) &&
        stackValue->IsString()) {
      String16 stackString =
          toProtocolString(isolate, stackValue.As<v8::String>());
      size_t pos = stackString.find("\n    at ");
      if (pos != String16::kNotFound) {
        stack = stackString.substring(pos);
      }
    }
  }

  std::optional<String16> message;
  {
    v8::Local<v8::Value> messageValue;
    if (object->Get(context, toV8String(isolate, "message"))
            .ToLocal(&messageValue) &&
        messageValue->IsString()) {
      String16 msg = toProtocolStringWithTypeCheck(isolate, messageValue);
      if (!msg.isEmpty()) message = msg;
    }
  }

  String16 description = name;
  if (message.has_value() && message->length() > 0) {
    description += ": " + *message;
  }

  if (stack.has_value() && stack->length() > 0) {
    description += *stack;
  }
  return description;
}

String16 descriptionForObject(v8::Isolate* isolate,
                              v8::Local<v8::Object> object) {
  return toProtocolString(isolate, object->GetConstructorName());
}

String16 descriptionForProxy(v8::Isolate* isolate, v8::Local<v8::Proxy> proxy) {
  v8::Local<v8::Value> target = proxy->GetTarget();
  if (target->IsObject()) {
    return String16::concat(
        "Proxy(", descriptionForObject(isolate, target.As<v8::Object>()), ")");
  }
  return String16("Proxy");
}

String16 descriptionForDate(v8::Local<v8::Context> context,
                            v8::Local<v8::Date> date) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::Local<v8::String> description = v8::debug::GetDateDescription(date);
  return toProtocolString(isolate, description);
}

String16 descriptionForScopeList(v8::Local<v8::Array> list) {
  return String16::concat(
      "Scopes[", String16::fromInteger(static_cast<size_t>(list->Length())),
      ']');
}

String16 descriptionForScope(v8::Local<v8::Context> context,
                             v8::Local<v8::Object> object) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::Local<v8::Value> value;
  if (!object->GetRealNamedProperty(context, toV8String(isolate, "description"))
           .ToLocal(&value)) {
    return String16();
  }
  return toProtocolStringWithTypeCheck(isolate, value);
}

String16 descriptionForCollection(v8::Isolate* isolate,
                                  v8::Local<v8::Object> object, size_t length) {
  String16 className = toProtocolString(isolate, object->GetConstructorName());
  return String16::concat(className, '(', String16::fromInteger(length), ')');
}

#if V8_ENABLE_WEBASSEMBLY
String16 descriptionForWasmValueObject(
    v8::Local<v8::Context> context,
    v8::Local<v8::debug::WasmValueObject> object) {
  v8::Isolate* isolate = context->GetIsolate();
  return toProtocolString(isolate, object->type());
}
#endif  // V8_ENABLE_WEBASSEMBLY

String16 descriptionForEntry(v8::Local<v8::Context> context,
                             v8::Local<v8::Object> object) {
  v8::Isolate* isolate = context->GetIsolate();
  String16 key;
  v8::Local<v8::Value> tmp;
  if (object->GetRealNamedProperty(context, toV8String(isolate, "key"))
          .ToLocal(&tmp)) {
    auto wrapper = ValueMirror::create(context, tmp);
    if (wrapper) {
      std::unique_ptr<ObjectPreview> preview;
      int limit = 5;
      wrapper->buildEntryPreview(context, &limit, &limit, &preview);
      if (preview) {
        key = preview->getDescription(String16());
        if (preview->getType() == RemoteObject::TypeEnum::String) {
          key = String16::concat('\"', key, '\"');
        }
      }
    }
  }

  String16 value;
  if (object->GetRealNamedProperty(context, toV8String(isolate, "value"))
          .ToLocal(&tmp)) {
    auto wrapper = ValueMirror::create(context, tmp);
    if (wrapper) {
      std::unique_ptr<ObjectPreview> preview;
      int limit = 5;
      wrapper->buildEntryPreview(context, &limit, &limit, &preview);
      if (preview) {
        value = preview->getDescription(String16());
        if (preview->getType() == RemoteObject::TypeEnum::String) {
          value = String16::concat('\"', value, '\"');
        }
      }
    }
  }

  return key.length() ? ("{" + key + " => " + value + "}") : value;
}

String16 descriptionForFunction(v8::Local<v8::Function> value) {
  v8::Isolate* isolate = value->GetIsolate();
  v8::Local<v8::String> description = v8::debug::GetFunctionDescription(value);
  return toProtocolString(isolate, description);
}

String16 descriptionForPrivateMethodList(v8::Local<v8::Array> list) {
  return String16::concat(
      "PrivateMethods[",
      String16::fromInteger(static_cast<size_t>(list->Length())), ']');
}

String16 descriptionForPrivateMethod(v8::Local<v8::Context> context,
                                     v8::Local<v8::Object> object) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::Local<v8::Value> value;
  if (!object->GetRealNamedProperty(context, toV8String(isolate, "value"))
           .ToLocal(&value)) {
    return String16();
  }
  DCHECK(value->IsFunction());
  return descriptionForFunction(value.As<v8::Function>());
}

String16 descriptionForNumber(v8::Local<v8::Number> value,
                              bool* unserializable) {
  *unserializable = true;
  double rawValue = value->Value();
  if (std::isnan(rawValue)) return "NaN";
  if (rawValue == 0.0 && std::signbit(rawValue)) return "-0";
  if (std::isinf(rawValue)) {
    return std::signbit(rawValue) ? "-Infinity" : "Infinity";
  }
  *unserializable = false;
  return String16::fromDouble(rawValue);
}

class ValueMirrorBase : public ValueMirror {
 public:
  ValueMirrorBase(v8::Isolate* isolate, v8::Local<v8::Value> value)
      : m_value(isolate, value) {}

  v8::Local<v8::Value> v8Value(v8::Isolate* isolate) const final {
    return m_value.Get(isolate);
  }

 private:
  v8::Global<v8::Value> m_value;
};

class PrimitiveValueMirror final : public ValueMirrorBase {
 public:
  PrimitiveValueMirror(v8::Isolate* isolate, v8::Local<v8::Primitive> value,
                       const String16& type)
      : ValueMirrorBase(isolate, value), m_type(type) {}

  Response buildRemoteObject(
      v8::Local<v8::Context> context, const WrapOptions& wrapOptions,
      std::unique_ptr<RemoteObject>* result) const override {
    std::unique_ptr<protocol::Value> protocolValue;
    v8::Local<v8::Value> value = v8Value(context->GetIsolate());
    toProtocolValue(context, value, &protocolValue);
    *result = RemoteObject::create()
                  .setType(m_type)
                  .setValue(std::move(protocolValue))
                  .build();
    if (value->IsNull()) (*result)->setSubtype(RemoteObject::SubtypeEnum::Null);
    return Response::Success();
  }

  void buildEntryPreview(
      v8::Local<v8::Context> context, int* nameLimit, int* indexLimit,
      std::unique_ptr<ObjectPreview>* preview) const override {
    v8::Local<v8::Value> value = v8Value(context->GetIsolate());
    *preview =
        ObjectPreview::create()
            .setType(m_type)
            .setDescription(descriptionForPrimitiveType(context, value))
            .setOverflow(false)
            .setProperties(std::make_unique<protocol::Array<PropertyPreview>>())
            .build();
    if (value->IsNull())
      (*preview)->setSubtype(RemoteObject::SubtypeEnum::Null);
  }

  void buildPropertyPreview(
      v8::Local<v8::Context> context, const String16& name,
      std::unique_ptr<PropertyPreview>* preview) const override {
    v8::Local<v8::Value> value = v8Value(context->GetIsolate());
    *preview = PropertyPreview::create()
                   .setName(name)
                   .setValue(abbreviateString(
                       descriptionForPrimitiveType(context, value), kMiddle))
                   .setType(m_type)
                   .build();
    if (value->IsNull())
      (*preview)->setSubtype(RemoteObject::SubtypeEnum::Null);
  }

  Response buildDeepSerializedValue(
      v8::Local<v8::Context> context, int maxDepth,
      v8::Local<v8::Object> additionalParameters,
      V8SerializationDuplicateTracker& duplicateTracker,
      std::unique_ptr<protocol::DictionaryValue>* result) const override {
    v8::Local<v8::Value> value = v8Value(context->GetIsolate());
    if (value->IsUndefined()) {
      *result = protocol::DictionaryValue::create();
      (*result)->setString(
          "type", protocol::Runtime::DeepSerializedValue::TypeEnum::Undefined);
      return Response::Success();
    }
    if (value->IsNull()) {
      *result = protocol::DictionaryValue::create();
      (*result)->setString(
          "type", protocol::Runtime::DeepSerializedValue::TypeEnum::Null);
      return Response::Success();
    }
    if (value->IsString()) {
      *result = protocol::DictionaryValue::create();
      (*result)->setString(
          "type", protocol::Runtime::DeepSerializedValue::TypeEnum::String);
      (*result)->setString("value", toProtocolString(context->GetIsolate(),
                                                     value.As<v8::String>()));
      return Response::Success();
    }
    if (value->IsBoolean()) {
      *result = protocol::DictionaryValue::create();
      (*result)->setString(
          "type", protocol::Runtime::DeepSerializedValue::TypeEnum::Boolean);
      (*result)->setBoolean("value", value.As<v8::Boolean>()->Value());
      return Response::Success();
    }

    // Fallback in case of unexpected type.
    bool isKnown;
    *result = duplicateTracker.LinkExistingOrCreate(value, &isKnown);
    if (isKnown) {
      return Response::Success();
    }

    (*result)->setString(
        "type", protocol::Runtime::DeepSerializedValue::TypeEnum::Object);
    return Response::Success();
  }

 private:
  String16 m_type;
  String16 m_subtype;
};

class NumberMirror final : public ValueMirrorBase {
 public:
  NumberMirror(v8::Isolate* isolate, v8::Local<v8::Number> value)
      : ValueMirrorBase(isolate, value) {}

  Response buildRemoteObject(
      v8::Local<v8::Context> context, const WrapOptions& wrapOptions,
      std::unique_ptr<RemoteObject>* result) const override {
    v8::Local<v8::Number> value =
        v8Value(context->GetIsolate()).As<v8::Number>();
    bool unserializable = false;
    String16 descriptionValue = descriptionForNumber(value, &unserializable);
    *result = RemoteObject::create()
                  .setType(RemoteObject::TypeEnum::Number)
                  .setDescription(descriptionValue)
                  .build();
    if (unserializable) {
      (*result)->setUnserializableValue(descriptionValue);
    } else {
      (*result)->setValue(protocol::FundamentalValue::create(value->Value()));
    }
    return Response::Success();
  }
  void buildPropertyPreview(
      v8::Local<v8::Context> context, const String16& name,
      std::unique_ptr<PropertyPreview>* result) const override {
    v8::Local<v8::Number> value =
        v8Value(context->GetIsolate()).As<v8::Number>();
    bool unserializable = false;
    *result = PropertyPreview::create()
                  .setName(name)
                  .setType(RemoteObject::TypeEnum::Number)
                  .setValue(descriptionForNumber(value, &unserializable))
                  .build();
  }
  void buildEntryPreview(
      v8::Local<v8::Context> context, int* nameLimit, int* indexLimit,
      std::unique_ptr<ObjectPreview>* preview) const override {
    v8::Local<v8::Number> value =
        v8Value(context->GetIsolate()).As<v8::Number>();
    bool unserializable = false;
    *preview =
        ObjectPreview::create()
            .setType(RemoteObject::TypeEnum::Number)
            .setDescription(descriptionForNumber(value, &unserializable))
            .setOverflow(false)
            .setProperties(std::make_unique<protocol::Array<PropertyPreview>>())
            .build();
  }

  Response buildDeepSerializedValue(
      v8::Local<v8::Context> context, int maxDepth,
      v8::Local<v8::Object> additionalParameters,
      V8SerializationDuplicateTracker& duplicateTracker,
      std::unique_ptr<protocol::DictionaryValue>* result) const override {
    *result = protocol::DictionaryValue::create();
    (*result)->setString(
        "type", protocol::Runtime::DeepSerializedValue::TypeEnum::Number);

    v8::Local<v8::Number> value =
        v8Value(context->GetIsolate()).As<v8::Number>();
    bool unserializable = false;
    String16 descriptionValue = descriptionForNumber(value, &unserializable);
    if (unserializable) {
      (*result)->setValue("value",
                          protocol::StringValue::create(descriptionValue));
    } else {
      (*result)->setValue("value", toProtocolValue(value->Value()));
    }
    return Response::Success();
  }
};

class BigIntMirror final : public ValueMirrorBase {
 public:
  BigIntMirror(v8::Isolate* isolate, v8::Local<v8::BigInt> value)
      : ValueMirrorBase(isolate, value) {}

  Response buildRemoteObject(
      v8::Local<v8::Context> context, const WrapOptions& wrapOptions,
      std::unique_ptr<RemoteObject>* result) const override {
    v8::Local<v8::BigInt> value =
        v8Value(context->GetIsolate()).As<v8::BigInt>();
    String16 description = descriptionForBigInt(context, value);
    *result = RemoteObject::create()
                  .setType(RemoteObject::TypeEnum::Bigint)
                  .setUnserializableValue(description)
                  .setDescription(abbreviateString(description, kMiddle))
                  .build();
    return Response::Success();
  }

  void buildPropertyPreview(v8::Local<v8::Context> context,
                            const String16& name,
                            std::unique_ptr<protocol::Runtime::PropertyPreview>*
                                preview) const override {
    v8::Local<v8::BigInt> value =
        v8Value(context->GetIsolate()).As<v8::BigInt>();
    *preview = PropertyPreview::create()
                   .setName(name)
                   .setType(RemoteObject::TypeEnum::Bigint)
                   .setValue(abbreviateString(
                       descriptionForBigInt(context, value), kMiddle))
                   .build();
  }

  void buildEntryPreview(v8::Local<v8::Context> context, int* nameLimit,
                         int* indexLimit,
                         std::unique_ptr<protocol::Runtime::ObjectPreview>*
                             preview) const override {
    v8::Local<v8::BigInt> value =
        v8Value(context->GetIsolate()).As<v8::BigInt>();
    *preview =
        ObjectPreview::create()
            .setType(RemoteObject::TypeEnum::Bigint)
            .setDescription(
                abbreviateString(descriptionForBigInt(context, value), kMiddle))
            .setOverflow(false)
            .setProperties(std::make_unique<protocol::Array<PropertyPreview>>())
            .build();
  }

  Response buildDeepSerializedValue(
      v8::Local<v8::Context> context, int maxDepth,
      v8::Local<v8::Object> additionalParameters,
      V8SerializationDuplicateTracker& duplicateTracker,
      std::unique_ptr<protocol::DictionaryValue>* result) const override {
    v8::Local<v8::BigInt> value =
        v8Value(context->GetIsolate()).As<v8::BigInt>();
    v8::Local<v8::String> stringValue =
        v8::debug::GetBigIntStringValue(context->GetIsolate(), value);

    *result = protocol::DictionaryValue::create();
    (*result)->setString(
        "type", protocol::Runtime::DeepSerializedValue::TypeEnum::Bigint);

    (*result)->setValue("value", protocol::StringValue::create(toProtocolString(
                                     context->GetIsolate(), stringValue)));
    return Response::Success();
  }
};

class SymbolMirror final : public ValueMirrorBase {
 public:
  SymbolMirror(v8::Isolate* isolate, v8::Local<v8::Symbol> value)
      : ValueMirrorBase(isolate, value) {}

  Response buildRemoteObject(
      v8::Local<v8::Context> context, const WrapOptions& wrapOptions,
      std::unique_ptr<RemoteObject>* result) const override {
    if (wrapOptions.mode == WrapMode::kJson) {
      return Response::ServerError("Object couldn't be returned by value");
    }
    v8::Local<v8::Symbol> value =
        v8Value(context->GetIsolate()).As<v8::Symbol>();
    *result = RemoteObject::create()
                  .setType(RemoteObject::TypeEnum::Symbol)
                  .setDescription(descriptionForSymbol(context, value))
                  .build();
    return Response::Success();
  }

  void buildPropertyPreview(v8::Local<v8::Context> context,
                            const String16& name,
                            std::unique_ptr<protocol::Runtime::PropertyPreview>*
                                preview) const override {
    v8::Local<v8::Symbol> value =
        v8Value(context->GetIsolate()).As<v8::Symbol>();
    *preview = PropertyPreview::create()
                   .setName(name)
                   .setType(RemoteObject::TypeEnum::Symbol)
                   .setValue(abbreviateString(
                       descriptionForSymbol(context, value), kEnd))
                   .build();
  }

  void buildEntryPreview(
      v8::Local<v8::Context> context, int* nameLimit, int* indexLimit,
      std::unique_ptr<ObjectPreview>* preview) const override {
    v8::Local<v8::Symbol> value =
        v8Value(context->GetIsolate()).As<v8::Symbol>();
    *preview =
        ObjectPreview::create()
            .setType(RemoteObject::TypeEnum::Symbol)
            .setDescription(descriptionForSymbol(context, value))
            .setOverflow(false)
            .setProperties(std::make_unique<protocol::Array<PropertyPreview>>())
            .build();
  }

  Response buildDeepSerializedValue(
      v8::Local<v8::Context> context, int maxDepth,
      v8::Local<v8::Object> additionalParameters,
      V8SerializationDuplicateTracker& duplicateTracker,
      std::unique_ptr<protocol::DictionaryValue>* result) const override {
    v8::Local<v8::Value> value = v8Value(context->GetIsolate());
    bool isKnown;
    *result = duplicateTracker.LinkExistingOrCreate(value, &isKnown);
    if (isKnown) {
      return Response::Success();
    }

    (*result)->setString(
        "type", protocol::Runtime::DeepSerializedValue::TypeEnum::Symbol);
    return Response::Success();
  }
};

class LocationMirror final : public ValueMirrorBase {
 public:
  static std::unique_ptr<LocationMirror> create(
      v8::Local<v8::Function> function) {
    return create(function, function->ScriptId(),
                  function->GetScriptLineNumber(),
                  function->GetScriptColumnNumber());
  }
  static std::unique_ptr<LocationMirror> createForGenerator(
      v8::Local<v8::Object> value) {
    v8::Local<v8::debug::GeneratorObject> generatorObject =
        v8::debug::GeneratorObject::Cast(value);
    if (!generatorObject->IsSuspended()) {
      return create(generatorObject->Function());
    }
    v8::Local<v8::debug::Script> script;
    if (!generatorObject->Script().ToLocal(&script)) return nullptr;
    v8::debug::Location suspendedLocation =
        generatorObject->SuspendedLocation();
    return create(value, script->Id(), suspendedLocation.GetLineNumber(),
                  suspendedLocation.GetColumnNumber());
  }

  Response buildRemoteObject(
      v8::Local<v8::Context> context, const WrapOptions& wrapOptions,
      std::unique_ptr<RemoteObject>* result) const override {
    auto location = protocol::DictionaryValue::create();
    location->setString("scriptId", String16::fromInteger(m_scriptId));
    location->setInteger("lineNumber", m_lineNumber);
    location->setInteger("columnNumber", m_columnNumber);
    *result = RemoteObject::create()
                  .setType(RemoteObject::TypeEnum::Object)
                  .setSubtype("internal#location")
                  .setDescription("Object")
                  .setValue(std::move(location))
                  .build();
    return Response::Success();
  }

  Response buildDeepSerializedValue(
      v8::Local<v8::Context> context, int maxDepth,
      v8::Local<v8::Object> additionalParameters,
      V8SerializationDuplicateTracker& duplicateTracker,
      std::unique_ptr<protocol::DictionaryValue>* result) const override {
    bool isKnown;
    v8::Local<v8::Value> value = v8Value(context->GetIsolate());
    *result = duplicateTracker.LinkExistingOrCreate(value, &isKnown);
    if (isKnown) {
      return Response::Success();
    }

    (*result)->setString(
        "type", protocol::Runtime::DeepSerializedValue::TypeEnum::Object);
    return Response::Success();
  }

 private:
  static std::unique_ptr<LocationMirror> create(v8::Local<v8::Object> value,
                                                int scriptId, int lineNumber,
                                                int columnNumber) {
    if (scriptId == v8::UnboundScript::kNoScriptId) return nullptr;
    if (lineNumber == v8::Function::kLineOffsetNotFound ||
        columnNumber == v8::Function::kLineOffsetNotFound) {
      return nullptr;
    }
    return std::unique_ptr<LocationMirror>(
        new LocationMirror(value, scriptId, lineNumber, columnNumber));
  }

  LocationMirror(v8::Local<v8::Object> value, int scriptId, int lineNumber,
                 int columnNumber)
      : ValueMirrorBase(value->GetIsolate(), value),
        m_scriptId(scriptId),
        m_lineNumber(lineNumber),
        m_columnNumber(columnNumber) {}

  int m_scriptId;
  int m_lineNumber;
  int m_columnNumber;
};

class FunctionMirror final : public ValueMirrorBase {
 public:
  explicit FunctionMirror(v8::Local<v8::Function> value)
      : ValueMirrorBase(value->GetIsolate(), value) {}

  Response buildRemoteObject(
      v8::Local<v8::Context> context, const WrapOptions& wrapOptions,
      std::unique_ptr<RemoteObject>* result) const override {
    v8::Local<v8::Function> value =
        v8Value(context->GetIsolate()).As<v8::Function>();
    // TODO(alph): drop this functi
```