Response:
Let's break down the thought process for analyzing the `custom-preview.cc` code.

1. **Initial Understanding of the Context:** The filename `custom-preview.cc` and the directory `v8/src/inspector` strongly suggest this code is related to the V8 JavaScript engine's debugging and inspection capabilities, specifically dealing with how objects are presented in the debugger's preview. The `#include` directives confirm this by bringing in inspector-related headers.

2. **High-Level Goal Identification:**  The core purpose seems to be generating "custom previews" for objects. This likely means providing a more informative or user-defined way to display object properties in debugging tools beyond the default representation.

3. **Keyword/Concept Spotting (and their implications):**

    * **`CustomPreview` (protocol namespace):** This immediately signals interaction with the Chrome DevTools Protocol (CDP). Custom previews are a feature exposed through this protocol.
    * **`devtoolsFormatters`:** This suggests a mechanism for users (or developers) to register custom formatting functions within the JavaScript environment.
    * **`header`, `body` (within formatters):**  This indicates a structured approach to custom previews, likely with a concise "header" and a more detailed "body" that can be shown on demand.
    * **`jsonML`:**  This is a strong indicator that the custom preview format is based on a JSON-like structure, probably for easy rendering in the DevTools UI. The `ML` likely stands for "Markup Language" or something similar.
    * **`substituteObjectTags`:** This function name points towards a process of replacing placeholders or special tags within the `jsonML` with actual object representations.
    * **`wrapObject`:**  This suggests interacting with the `InjectedScript` to obtain a representation of a JavaScript object suitable for sending over the CDP.
    * **`reportError`:**  Error handling is crucial, especially when user-provided code is involved. This function is used to report issues during the custom preview generation.
    * **`v8::TryCatch`:**  Used extensively for exception handling within the V8 engine.
    * **`v8::FunctionCallbackInfo`:**  The signature of a V8 callback function, confirming interaction with JavaScript.
    * **`MicrotasksScope`:**  Indicates that the custom preview generation might involve or be sensitive to the execution of microtasks.
    * **`WrapOptions({WrapMode::kIdOnly})`:**  Optimization technique to avoid sending the full object structure initially, likely fetching it on demand if the body is expanded.

4. **Function-Level Analysis:**

    * **`reportError` (both overloads):**  Simple error reporting mechanism, crucial for debugging the custom preview process. The second overload allows providing a specific error message.
    * **`getInjectedScript`:**  Essential for interacting with the JavaScript context from the C++ side. `InjectedScript` provides methods to execute JavaScript code and wrap/unwrap objects.
    * **`substituteObjectTags`:**  The core logic for recursively processing the `jsonML` and replacing `"object"` tags with wrapped object representations. The `maxDepth` parameter is important for preventing infinite recursion.
    * **`bodyCallback`:**  This is the callback function invoked when the debugger requests the detailed body of a custom preview. It executes the user-defined `body` function in JavaScript.
    * **`generateCustomPreview`:** The main function responsible for orchestrating the custom preview generation. It retrieves the formatters, calls the `header` function, and potentially sets up the `bodyCallback`.

5. **Control Flow and Logic Reconstruction:**

    * The `generateCustomPreview` function is the entry point.
    * It fetches the `devtoolsFormatters` array from the global scope.
    * It iterates through the formatters, calling the `header` function of each formatter with the target object and optional config.
    * If a `header` function returns a non-empty `jsonML`, it's considered a match.
    * `substituteObjectTags` is called to process the `jsonML`, replacing `"object"` tags.
    * If the formatter has a `hasBody` function that returns true, a `bodyCallback` is created and registered. This callback will be invoked later if the user expands the preview in the debugger.

6. **Identifying Potential Issues and User Errors:**

    * **Exceptions in user-provided code:** The extensive use of `v8::TryCatch` highlights the awareness of potential errors in the JavaScript formatter functions.
    * **Incorrect return types from formatter functions:**  The code checks if `header` and `body` return arrays. Returning the wrong type will lead to errors.
    * **Missing or incorrect attributes in `jsonML`:** The checks within `substituteObjectTags` for the `"object"` attribute and its structure are important.
    * **Infinite recursion in `jsonML`:** The `maxDepth` parameter in `substituteObjectTags` is crucial to prevent stack overflow errors if the `jsonML` structure is deeply nested.
    * **Incorrect usage of `devtoolsFormatters`:** Users might not register their formatters correctly or might write formatters that throw errors.

7. **JavaScript Example Construction:** Based on the identified concepts (formatters, `header`, `body`, `jsonML`), construct a simple example illustrating how these pieces fit together in JavaScript.

8. **Torque Check:** The file extension `.cc` clearly indicates this is C++ code, not Torque.

9. **Review and Refinement:** Read through the analysis, ensuring clarity, accuracy, and completeness. Organize the information logically.

By following these steps, we can systematically analyze the C++ code and derive a comprehensive understanding of its functionality, its relationship to JavaScript, potential error scenarios, and how it contributes to the overall debugging experience in V8.
This C++ source file, `v8/src/inspector/custom-preview.cc`, is responsible for generating **custom previews** of JavaScript objects in the Chrome DevTools. It allows developers to define how certain objects should be displayed in the debugger's console and object inspector, providing more informative and user-friendly representations beyond the default stringification.

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Registering Custom Formatters:**  The code interacts with a JavaScript mechanism (likely the `devtoolsFormatters` array in the global scope) where developers can register custom formatting functions for specific object types.

2. **Matching Formatters to Objects:** When the DevTools needs to display an object, this code iterates through the registered formatters to find one that can handle the object. This matching is done by calling the formatter's `header` function.

3. **Generating the Header Preview:** If a matching formatter is found, its `header` function is executed. This function should return a JSON-like structure called `jsonML` (likely short for JSON Markup Language). This `jsonML` describes how the object's header should be rendered in the DevTools.

4. **Generating the Body Preview (Optional):** Formatters can also have a `hasBody` function. If this function returns `true`, the formatter also has a `body` function. The `body` function is called when the user expands the preview in the DevTools to see more details. The `body` function also returns `jsonML` to describe the detailed view.

5. **Substituting Object Tags:**  Within the `jsonML` returned by both `header` and `body`, there can be special `"object"` tags. The `substituteObjectTags` function is responsible for finding these tags and replacing them with a proper representation of the referenced JavaScript object. This involves using the `InjectedScript` to wrap the object and obtain its properties.

6. **Error Handling:** The code includes robust error handling using `v8::TryCatch` to catch exceptions that might occur during the execution of the custom formatter functions. It reports these errors to the DevTools console.

**Relation to JavaScript and Examples:**

Yes, this code directly relates to JavaScript functionality. Developers define the custom preview logic using JavaScript functions.

**JavaScript Example of Registering a Custom Formatter:**

```javascript
if (typeof window !== 'undefined') { // Check if running in a browser-like environment
  if (!window.devtoolsFormatters) {
    window.devtoolsFormatters = [];
  }

  window.devtoolsFormatters.push({
    header: function(obj, config) {
      if (obj instanceof Date) {
        return ["span", { style: "color: blue;" }, "Date: ", obj.toLocaleDateString()];
      }
      return null; // Indicate this formatter doesn't apply
    },
    hasBody: function(obj, config) {
      return obj instanceof Date;
    },
    body: function(obj, config) {
      return ["ol",
        ["li", "Time: " + obj.toLocaleTimeString()],
        ["li", "UTC Time: " + obj.toUTCString()]
      ];
    }
  });
}

// Example usage in the console:
const myDate = new Date();
console.log(myDate); // The DevTools console will use the custom formatter
```

**Explanation of the JavaScript Example:**

* We check if `window.devtoolsFormatters` exists and create it if it doesn't.
* We push an object containing our custom formatter functions into the array.
* **`header` function:**
    * Takes the object (`obj`) and an optional `config` object as arguments.
    * Checks if the object is an instance of `Date`.
    * If it is, it returns a `jsonML` structure representing the header:
        * `["span", { style: "color: blue;" }, "Date: ", obj.toLocaleDateString()]`  This tells the DevTools to render a `<span>` element with blue text, displaying "Date: " followed by the localized date string.
    * If the object is not a `Date`, it returns `null`, indicating that this formatter doesn't handle this object.
* **`hasBody` function:**
    * Also checks if the object is a `Date`.
    * Returns `true` if it is, indicating that there's a detailed body to show.
* **`body` function:**
    * For `Date` objects, it returns `jsonML` for the body:
        * `["ol", ["li", "Time: " + obj.toLocaleTimeString()], ["li", "UTC Time: " + obj.toUTCString()]]` This creates an ordered list (`<ol>`) with two list items (`<li>`) showing the local time and UTC time.

**Code Logic Inference (with Hypothetical Input and Output):**

**Hypothetical Input:**

* A JavaScript object: `const myObject = { name: "Example", value: 123 };`
* A registered custom formatter:

```javascript
window.devtoolsFormatters.push({
  header: function(obj) {
    if (typeof obj === 'object' && obj !== null && obj.name) {
      return ["b", "Custom Object: ", obj.name];
    }
    return null;
  }
});
```

**Hypothetical Output (as seen in the DevTools console when `console.log(myObject)` is called):**

Instead of the default `Object {name: "Example", value: 123}`, the console might show:

**Custom Object: Example** (rendered in bold)

**Explanation:**

1. The `generateCustomPreview` function in `custom-preview.cc` would be triggered when the DevTools needs to display `myObject`.
2. It would iterate through the `devtoolsFormatters`.
3. The `header` function of our custom formatter would be called with `myObject`.
4. The `header` function would return `["b", "Custom Object: ", "Example"]`.
5. The `generateCustomPreview` function would then construct a `CustomPreview` object with the header set to this `jsonML`, instructing the DevTools to render it as bold text.

**Common Programming Errors (from a user's perspective writing custom formatters):**

1. **Incorrect `jsonML` Structure:** Returning `jsonML` that doesn't conform to the expected format (e.g., not starting with a tag name string, incorrect attribute syntax). This can lead to errors in the DevTools or the preview not rendering correctly.

   ```javascript
   // Incorrect - missing tag name
   header: function(obj) {
     return { text: "Wrong format" };
   }

   // Correct
   header: function(obj) {
     return ["span", "Correct format"];
   }
   ```

2. **Throwing Errors in Formatter Functions:** If the `header` or `body` functions throw an error, the custom preview will likely fail, and the DevTools might revert to the default representation or show an error message. Always use `try...catch` within your formatter functions for robustness.

   ```javascript
   header: function(obj) {
     if (obj.someUndefinedProperty.length > 0) { // This will throw an error
       return ["span", "Something"];
     }
     return null;
   }

   // Corrected with error handling
   header: function(obj) {
     try {
       if (obj.someUndefinedProperty && obj.someUndefinedProperty.length > 0) {
         return ["span", "Something"];
       }
     } catch (e) {
       console.error("Error in custom formatter:", e);
     }
     return null;
   }
   ```

3. **Not Returning `null` When the Formatter Doesn't Apply:** If a formatter's `header` function doesn't apply to the given object, it's crucial to return `null`. Otherwise, the DevTools might incorrectly use this formatter.

   ```javascript
   header: function(obj) {
     // Forgot to check the object type
     return ["span", "Might apply incorrectly"];
   }

   // Corrected
   header: function(obj) {
     if (typeof obj === 'number') {
       return ["span", "A number: " + obj];
     }
     return null;
   }
   ```

4. **Infinite Recursion in `jsonML` (if manually creating complex structures):** If you are dynamically generating complex `jsonML` structures, be careful not to create infinite loops or deeply nested structures that could cause performance issues or errors. The `substituteObjectTags` function in the C++ code has a `maxDepth` parameter to mitigate this for object substitution, but user-generated `jsonML` could still have issues.

**Regarding `.tq` extension:**

The provided source code `v8/src/inspector/custom-preview.cc` has the `.cc` extension, which signifies a **C++ source file**. If a file in the V8 project had a `.tq` extension, it would indeed indicate a **Torque source file**. Torque is a domain-specific language used within V8 for generating efficient code for built-in JavaScript functions and runtime operations. The current file is definitely C++.

### 提示词
```
这是目录为v8/src/inspector/custom-preview.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/custom-preview.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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