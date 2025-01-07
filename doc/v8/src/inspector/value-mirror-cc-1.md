Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/inspector/value-mirror.cc`. The summary should also address specific points:
1. Check if the filename ends with `.tq` (it doesn't).
2. Explain the relationship with JavaScript, providing examples.
3. Provide code logic reasoning with input/output examples.
4. Illustrate common programming errors.
5. This is part 2 of a 3-part series, so focus on summarizing the *current* code's functionality.

**Plan:**

1. **High-level overview:**  The code seems to be involved in representing JavaScript values in a way that's suitable for debugging and inspection, likely within the context of the Chrome DevTools Protocol. It defines classes like `ValueMirror`, `ObjectMirror`, `FunctionMirror`, and structures like `PropertyMirror`, `InternalPropertyMirror`, which suggest mirroring JavaScript's object model.
2. **Class-specific functionality:**
    *   **`FunctionMirror`:**  Deals with representing JavaScript functions. It can build `RemoteObject` representations (for sending over the protocol) and `ObjectPreview` representations (for concise summaries).
    *   **`ObjectMirror`:**  Handles general JavaScript objects, similar to `FunctionMirror` but with more emphasis on property enumeration and preview generation. It also handles deep serialization.
    *   **Helper functions:**  `isArrayLike`, `getEntries`, `getPropertiesForPreview`, `getInternalPropertiesForPreview`, `getPrivatePropertiesForPreview` are used to gather information about objects and their properties.
    *   **Property accumulators:**  `PreviewPropertyAccumulator` helps in filtering and collecting properties for previews.
    *   **Native getter/setter creation:**  `createNativeGetter` and `createNativeSetter` are used to represent native JavaScript accessors.
3. **Relationship with JavaScript:** The code directly manipulates V8's internal representation of JavaScript values (`v8::Local<v8::Value>`, `v8::Local<v8::Object>`, etc.). It's about exposing these values in a structured way for debugging.
4. **Code logic reasoning:** Focus on the preview generation logic, which involves limiting the number of properties and entries displayed.
5. **Common programming errors:**  Think about scenarios where the inspector might fail to retrieve or represent values correctly, such as errors during property access or issues with asynchronous operations.

**Self-Correction/Refinement:**

*   The request emphasizes functionality. Avoid getting bogged down in the low-level details of the V8 API unless it directly clarifies the purpose.
*   The "part 2 of 3" instruction means focusing on the functionality *within this specific code block*, not trying to anticipate the content of parts 1 or 3.
*   Ensure the JavaScript examples are clear and directly relate to the C++ code's purpose.
根据您提供的代码片段，`v8/src/inspector/value-mirror.cc` 的主要功能是 **为 JavaScript 的值创建镜像表示，以便在调试器或检查器中进行检查和展示**。

这里归纳一下其功能：

**核心功能：创建值的镜像表示 (Mirroring)**

*   **`ValueMirror` 类及其子类 (`FunctionMirror`, `ObjectMirror`)**:  这些类是核心，负责将 V8 中的 `v8::Value` 转换成更易于调试器使用的表示形式。
*   **`RemoteObject`**:  这些镜像表示最终会被构建成 `RemoteObject` 协议对象，这是 Chrome DevTools Protocol (CDP) 中用于表示远程 JavaScript 对象的标准方式。
*   **区分不同类型的值**:  针对函数 (`FunctionMirror`) 和普通对象 (`ObjectMirror`) 有不同的处理逻辑，以便更准确地反映其特性。

**关键能力：构建不同粒度的表示**

*   **`buildRemoteObject`**:  创建详细的 `RemoteObject` 表示，可以包含类型、类名、描述和值（对于简单类型）。对于复杂对象，可以选择以 JSON 格式或更结构化的方式表示。
*   **`buildPropertyPreview`**:  创建属性的简短预览，通常只包含名称和类型，用于在列表中快速展示。
*   **`buildEntryPreview`**:  创建 Map 或 Set 等数据结构中条目的预览。
*   **`buildObjectPreview`**:  创建对象的属性的预览列表，限制了显示的属性数量，用于在调试器中提供对象的概览。
*   **`buildDeepSerializedValue`**:  用于将对象深度序列化为协议值，用于更复杂的数据传输。它会处理循环引用，避免无限递归。

**辅助功能：收集属性信息**

*   **`getPropertiesForPreview`**:  获取用于预览的对象属性，并进行过滤（例如，排除 `length` 属性对于数组类对象）。
*   **`getInternalPropertiesForPreview`**:  获取对象的内部属性（例如，Promise 的状态）。
*   **`getPrivatePropertiesForPreview`**:  获取对象的私有属性。
*   **`isArrayLike`**:  判断一个对象是否类似于数组（有 `length` 属性）。
*   **`EntryMirror::getEntries`**:  获取对象中的键值对条目，用于 Map 和 Set 等结构。
*   **`PreviewPropertyAccumulator`**:  一个用于累积和过滤属性的辅助类，用于预览功能。

**与 JavaScript 的关系 (通过 `v8::Local` 类型体现)**

这段 C++ 代码直接操作 V8 引擎中的 JavaScript 对象和值，使用的类型如 `v8::Local<v8::Value>`, `v8::Local<v8::Object>`, `v8::Local<v8::Function>` 等，都是 V8 提供的用于访问和操作 JavaScript 对象的接口。

**JavaScript 示例**

假设在 JavaScript 中有以下代码：

```javascript
function myFunction(a, b) {
  console.log(a + b);
}

const myObject = {
  name: "example",
  value: 123,
  method: function() {}
};

const myArray = [1, 2, 3];
```

`value-mirror.cc` 中的代码会负责将 `myFunction`、`myObject` 和 `myArray` 这些 JavaScript 值转换为可以在调试器中查看和操作的 `RemoteObject` 或 `ObjectPreview`。例如，当你在 Chrome DevTools 的 Console 中输入 `myObject` 并展开它时，显示出来的属性列表 (name, value, method) 就是由 `getPropertiesForPreview` 等函数收集并格式化的。

**代码逻辑推理示例**

**假设输入：** 一个 JavaScript 对象 `myObject = { a: 1, b: { c: 2 }, d: function() {} }`，并且调试器要求生成 `myObject` 的对象预览，`nameLimit` 设置为 1。

**推理过程：**

1. `getPropertiesForPreview` 函数会被调用，`nameLimit` 为 1。
2. `PreviewPropertyAccumulator` 会被创建，`m_nameLimit` 初始化为 1。
3. 遍历 `myObject` 的属性：
    *   属性 `a`:  `Add` 方法被调用，`m_nameLimit` 减为 0，属性 `a` 被添加到预览。
    *   属性 `b`:  `Add` 方法被调用，由于 `m_nameLimit` 已经为 0，`m_overflow` 被设置为 `true`，并返回 `false`，停止添加更多命名属性。
    *   属性 `d`:  不会被处理，因为预览已停止添加命名属性。

**输出：** 对象预览将包含属性 `a`，并且 `overflow` 标志会被设置为 `true`，表示还有其他属性未显示。

**用户常见的编程错误 (可能与 `value-mirror.cc` 的功能相关)**

虽然 `value-mirror.cc` 本身是 V8 的内部代码，但它处理的是如何展示 JavaScript 的值，因此与用户可能遇到的编程错误间接相关。 例如：

*   **无限递归的对象结构**:  如果 JavaScript 对象存在循环引用 (例如 `a.b = a`)，深度序列化逻辑需要能够处理，避免无限循环。 如果处理不当，可能导致调试器卡死或崩溃。 `buildDeepSerializedValue` 中的 `duplicateTracker` 就是为了解决这个问题。
*   **访问不存在的属性导致错误**:  虽然 `value-mirror.cc` 会尝试捕获异常，但用户在代码中访问不存在的属性仍然是常见的错误，调试器会显示 `undefined` 或错误信息，这最终会通过 `ValueMirror` 的机制反映出来。

总而言之，`v8/src/inspector/value-mirror.cc` 是 V8 调试基础设施的关键组成部分，它负责将运行时的 JavaScript 值转换为调试器可以理解和展示的形式，使得开发者能够方便地检查程序状态。

Prompt: 
```
这是目录为v8/src/inspector/value-mirror.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/inspector/value-mirror.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
onality.
    if (wrapOptions.mode == WrapMode::kJson) {
      std::unique_ptr<protocol::Value> protocolValue;
      Response response = toProtocolValue(context, value, &protocolValue);
      if (!response.IsSuccess()) return response;
      *result = RemoteObject::create()
                    .setType(RemoteObject::TypeEnum::Function)
                    .setValue(std::move(protocolValue))
                    .build();
    } else {
      *result = RemoteObject::create()
                    .setType(RemoteObject::TypeEnum::Function)
                    .setClassName(toProtocolStringWithTypeCheck(
                        context->GetIsolate(), value->GetConstructorName()))
                    .setDescription(descriptionForFunction(value))
                    .build();
    }
    return Response::Success();
  }

  void buildPropertyPreview(
      v8::Local<v8::Context> context, const String16& name,
      std::unique_ptr<PropertyPreview>* result) const override {
    *result = PropertyPreview::create()
                  .setName(name)
                  .setType(RemoteObject::TypeEnum::Function)
                  .setValue(String16())
                  .build();
  }
  void buildEntryPreview(
      v8::Local<v8::Context> context, int* nameLimit, int* indexLimit,
      std::unique_ptr<ObjectPreview>* preview) const override {
    v8::Local<v8::Function> value =
        v8Value(context->GetIsolate()).As<v8::Function>();
    *preview =
        ObjectPreview::create()
            .setType(RemoteObject::TypeEnum::Function)
            .setDescription(descriptionForFunction(value))
            .setOverflow(false)
            .setProperties(std::make_unique<protocol::Array<PropertyPreview>>())
            .build();
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
        "type", protocol::Runtime::DeepSerializedValue::TypeEnum::Function);
    return Response::Success();
  }
};

bool isArrayLike(v8::Local<v8::Context> context, v8::Local<v8::Object> object,
                 size_t* length) {
  if (object->IsArray()) {
    *length = object.As<v8::Array>()->Length();
    return true;
  }
  if (object->IsArgumentsObject()) {
    v8::Isolate* isolate = context->GetIsolate();
    v8::TryCatch tryCatch(isolate);
    v8::MicrotasksScope microtasksScope(
        context, v8::MicrotasksScope::kDoNotRunMicrotasks);
    v8::Local<v8::Value> lengthDescriptor;
    if (!object
             ->GetOwnPropertyDescriptor(context, toV8String(isolate, "length"))
             .ToLocal(&lengthDescriptor)) {
      return false;
    }
    v8::Local<v8::Value> lengthValue;
    if (!lengthDescriptor->IsObject() ||
        !lengthDescriptor.As<v8::Object>()
             ->Get(context, toV8String(isolate, "value"))
             .ToLocal(&lengthValue) ||
        !lengthValue->IsUint32()) {
      return false;
    }
    *length = lengthValue.As<v8::Uint32>()->Value();
    return true;
  }
  return false;
}

struct EntryMirror {
  std::unique_ptr<ValueMirror> key;
  std::unique_ptr<ValueMirror> value;

  static bool getEntries(v8::Local<v8::Context> context,
                         v8::Local<v8::Object> object, size_t limit,
                         bool* overflow, std::vector<EntryMirror>* mirrors) {
    bool isKeyValue = false;
    v8::Local<v8::Array> entries;
    if (!object->PreviewEntries(&isKeyValue).ToLocal(&entries)) return false;
    for (uint32_t i = 0; i < entries->Length(); i += isKeyValue ? 2 : 1) {
      v8::Local<v8::Value> tmp;

      std::unique_ptr<ValueMirror> keyMirror;
      if (isKeyValue && entries->Get(context, i).ToLocal(&tmp)) {
        keyMirror = ValueMirror::create(context, tmp);
      }
      std::unique_ptr<ValueMirror> valueMirror;
      if (entries->Get(context, isKeyValue ? i + 1 : i).ToLocal(&tmp)) {
        valueMirror = ValueMirror::create(context, tmp);
      } else {
        continue;
      }
      if (mirrors->size() == limit) {
        *overflow = true;
        return true;
      }
      mirrors->emplace_back(
          EntryMirror{std::move(keyMirror), std::move(valueMirror)});
    }
    return !mirrors->empty();
  }
};

class PreviewPropertyAccumulator : public ValueMirror::PropertyAccumulator {
 public:
  PreviewPropertyAccumulator(v8::Isolate* isolate,
                             const std::vector<String16>& blocklist,
                             int skipIndex, int* nameLimit, int* indexLimit,
                             bool* overflow,
                             std::vector<PropertyMirror>* mirrors)
      : m_isolate(isolate),
        m_blocklist(blocklist),
        m_skipIndex(skipIndex),
        m_nameLimit(nameLimit),
        m_indexLimit(indexLimit),
        m_overflow(overflow),
        m_mirrors(mirrors) {}

  bool Add(PropertyMirror mirror) override {
    if (mirror.exception) return true;
    if ((!mirror.getter || !mirror.getter->v8Value(m_isolate)->IsFunction()) &&
        !mirror.value) {
      return true;
    }
    if (!mirror.isOwn && !mirror.isSynthetic) return true;
    if (std::find(m_blocklist.begin(), m_blocklist.end(), mirror.name) !=
        m_blocklist.end()) {
      return true;
    }
    if (mirror.isIndex && m_skipIndex > 0) {
      --m_skipIndex;
      if (m_skipIndex > 0) return true;
    }
    int* limit = mirror.isIndex ? m_indexLimit : m_nameLimit;
    if (!*limit) {
      *m_overflow = true;
      return false;
    }
    --*limit;
    m_mirrors->push_back(std::move(mirror));
    return true;
  }

 private:
  v8::Isolate* m_isolate;
  std::vector<String16> m_blocklist;
  int m_skipIndex;
  int* m_nameLimit;
  int* m_indexLimit;
  bool* m_overflow;
  std::vector<PropertyMirror>* m_mirrors;
};

bool getPropertiesForPreview(v8::Local<v8::Context> context,
                             v8::Local<v8::Object> object, int* nameLimit,
                             int* indexLimit, bool* overflow,
                             std::vector<PropertyMirror>* properties) {
  std::vector<String16> blocklist;
  size_t length = 0;
  if (isArrayLike(context, object, &length) || object->IsStringObject()) {
    blocklist.push_back("length");
#if V8_ENABLE_WEBASSEMBLY
  } else if (v8::debug::WasmValueObject::IsWasmValueObject(object)) {
    blocklist.push_back("type");
#endif  // V8_ENABLE_WEBASSEMBLY
  } else {
    auto clientSubtype = clientFor(context)->valueSubtype(object);
    if (clientSubtype && toString16(clientSubtype->string()) == "array") {
      blocklist.push_back("length");
    }
  }
  if (object->IsArrayBuffer() || object->IsSharedArrayBuffer()) {
    blocklist.push_back("[[Int8Array]]");
    blocklist.push_back("[[Uint8Array]]");
    blocklist.push_back("[[Int16Array]]");
    blocklist.push_back("[[Int32Array]]");
  }
  blocklist.push_back("constructor");
  int skipIndex = object->IsStringObject()
                      ? object.As<v8::StringObject>()->ValueOf()->Length() + 1
                      : -1;
  PreviewPropertyAccumulator accumulator(context->GetIsolate(), blocklist,
                                         skipIndex, nameLimit, indexLimit,
                                         overflow, properties);
  return ValueMirror::getProperties(context, object, false, false, false,
                                    &accumulator);
}

void getInternalPropertiesForPreview(
    v8::Local<v8::Context> context, v8::Local<v8::Object> object,
    int* nameLimit, bool* overflow,
    std::vector<InternalPropertyMirror>* properties) {
  std::vector<InternalPropertyMirror> mirrors;
  ValueMirror::getInternalProperties(context, object, &mirrors);
  std::vector<String16> allowlist;
  if (object->IsBooleanObject() || object->IsNumberObject() ||
      object->IsStringObject() || object->IsSymbolObject() ||
      object->IsBigIntObject()) {
    allowlist.emplace_back("[[PrimitiveValue]]");
  } else if (object->IsPromise()) {
    allowlist.emplace_back("[[PromiseState]]");
    allowlist.emplace_back("[[PromiseResult]]");
  } else if (object->IsGeneratorObject()) {
    allowlist.emplace_back("[[GeneratorState]]");
  } else if (object->IsWeakRef()) {
    allowlist.emplace_back("[[WeakRefTarget]]");
  }
  for (auto& mirror : mirrors) {
    if (std::find(allowlist.begin(), allowlist.end(), mirror.name) ==
        allowlist.end()) {
      continue;
    }
    if (!*nameLimit) {
      *overflow = true;
      return;
    }
    --*nameLimit;
    properties->push_back(std::move(mirror));
  }
}

void getPrivatePropertiesForPreview(
    v8::Local<v8::Context> context, v8::Local<v8::Object> object,
    int* nameLimit, bool* overflow,
    protocol::Array<PropertyPreview>* privateProperties) {
  std::vector<PrivatePropertyMirror> mirrors =
      ValueMirror::getPrivateProperties(context, object,
                                        /* accessPropertiesOnly */ false);
  for (auto& mirror : mirrors) {
    std::unique_ptr<PropertyPreview> propertyPreview;
    if (mirror.value) {
      mirror.value->buildPropertyPreview(context, mirror.name,
                                         &propertyPreview);
    } else {
      propertyPreview = PropertyPreview::create()
                            .setName(mirror.name)
                            .setType(PropertyPreview::TypeEnum::Accessor)
                            .build();
    }
    if (!propertyPreview) continue;
    if (!*nameLimit) {
      *overflow = true;
      return;
    }
    --*nameLimit;
    privateProperties->emplace_back(std::move(propertyPreview));
  }
}

class ObjectMirror final : public ValueMirrorBase {
 public:
  ObjectMirror(v8::Local<v8::Object> value, const String16& description)
      : ValueMirrorBase(value->GetIsolate(), value),
        m_description(description),
        m_hasSubtype(false) {}
  ObjectMirror(v8::Local<v8::Object> value, const String16& subtype,
               const String16& description)
      : ValueMirrorBase(value->GetIsolate(), value),
        m_description(description),
        m_hasSubtype(true),
        m_subtype(subtype) {}

  Response buildRemoteObject(
      v8::Local<v8::Context> context, const WrapOptions& wrapOptions,
      std::unique_ptr<RemoteObject>* result) const override {
    v8::Isolate* isolate = context->GetIsolate();
    v8::Local<v8::Object> value = v8Value(isolate).As<v8::Object>();
    if (wrapOptions.mode == WrapMode::kJson) {
      std::unique_ptr<protocol::Value> protocolValue;
      Response response = toProtocolValue(context, value, &protocolValue);
      if (!response.IsSuccess()) return response;
      *result = RemoteObject::create()
                    .setType(RemoteObject::TypeEnum::Object)
                    .setValue(std::move(protocolValue))
                    .build();
    } else {
      *result = RemoteObject::create()
                    .setType(RemoteObject::TypeEnum::Object)
                    .setClassName(
                        toProtocolString(isolate, value->GetConstructorName()))
                    .setDescription(m_description)
                    .build();
      if (m_hasSubtype) (*result)->setSubtype(m_subtype);
      if (wrapOptions.mode == WrapMode::kPreview) {
        std::unique_ptr<ObjectPreview> previewValue;
        int nameLimit = 5;
        int indexLimit = 100;
        buildObjectPreview(context, false, &nameLimit, &indexLimit,
                           &previewValue);
        (*result)->setPreview(std::move(previewValue));
      }
    }
    return Response::Success();
  }

  void buildObjectPreview(
      v8::Local<v8::Context> context, bool generatePreviewForTable,
      int* nameLimit, int* indexLimit,
      std::unique_ptr<ObjectPreview>* result) const override {
    buildObjectPreviewInternal(context, false /* forEntry */,
                               generatePreviewForTable, nameLimit, indexLimit,
                               result);
  }

  void buildEntryPreview(
      v8::Local<v8::Context> context, int* nameLimit, int* indexLimit,
      std::unique_ptr<ObjectPreview>* result) const override {
    buildObjectPreviewInternal(context, true /* forEntry */,
                               false /* generatePreviewForTable */, nameLimit,
                               indexLimit, result);
  }

  void buildPropertyPreview(
      v8::Local<v8::Context> context, const String16& name,
      std::unique_ptr<PropertyPreview>* result) const override {
    *result = PropertyPreview::create()
                  .setName(name)
                  .setType(RemoteObject::TypeEnum::Object)
                  .setValue(abbreviateString(
                      m_description,
                      m_subtype == RemoteObject::SubtypeEnum::Regexp ? kMiddle
                                                                     : kEnd))
                  .build();
    if (m_hasSubtype) (*result)->setSubtype(m_subtype);
  }

  Response buildDeepSerializedValue(
      v8::Local<v8::Context> context, int maxDepth,
      v8::Local<v8::Object> additionalParameters,
      V8SerializationDuplicateTracker& duplicateTracker,
      std::unique_ptr<protocol::DictionaryValue>* result) const override {
    v8::Local<v8::Object> value =
        v8Value(context->GetIsolate()).As<v8::Object>();
    maxDepth = std::min(kMaxProtocolDepth, maxDepth);
    bool isKnown;
    *result = duplicateTracker.LinkExistingOrCreate(value, &isKnown);
    if (isKnown) {
      return Response::Success();
    }

    // Check if embedder implemented custom serialization.
    std::unique_ptr<v8_inspector::DeepSerializationResult>
        embedderDeepSerializedResult = clientFor(context)->deepSerialize(
            value, maxDepth, additionalParameters);
    if (embedderDeepSerializedResult) {
      // Embedder-implemented serialization.

      if (!embedderDeepSerializedResult->isSuccess)
        return Response::ServerError(
            toString16(embedderDeepSerializedResult->errorMessage->string())
                .utf8());

      (*result)->setString(
          "type",
          toString16(
              embedderDeepSerializedResult->serializedValue->type->string()));
      v8::Local<v8::Value> v8Value;
      if (embedderDeepSerializedResult->serializedValue->value.ToLocal(
              &v8Value)) {
        // Embedder-implemented serialization has value.
        std::unique_ptr<protocol::Value> protocolValue;
        Response response = toProtocolValue(context, v8Value, &protocolValue);
        if (!response.IsSuccess()) return response;
        (*result)->setValue("value", std::move(protocolValue));
      }
      return Response::Success();
    }

    // No embedder-implemented serialization. Serialize as V8 Object.
    return V8DeepSerializer::serializeV8Value(value, context, maxDepth,
                                              additionalParameters,
                                              duplicateTracker, *(*result));
  }

 private:
  void buildObjectPreviewInternal(
      v8::Local<v8::Context> context, bool forEntry,
      bool generatePreviewForTable, int* nameLimit, int* indexLimit,
      std::unique_ptr<ObjectPreview>* result) const {
    auto properties = std::make_unique<protocol::Array<PropertyPreview>>();
    std::unique_ptr<protocol::Array<EntryPreview>> entriesPreview;
    bool overflow = false;

    v8::Local<v8::Value> value = v8Value(context->GetIsolate());
    while (value->IsProxy()) value = value.As<v8::Proxy>()->GetTarget();

    if (value->IsObject() && !value->IsProxy()) {
      v8::Local<v8::Object> objectForPreview = value.As<v8::Object>();
      std::vector<InternalPropertyMirror> internalProperties;
      getInternalPropertiesForPreview(context, objectForPreview, nameLimit,
                                      &overflow, &internalProperties);
      for (size_t i = 0; i < internalProperties.size(); ++i) {
        std::unique_ptr<PropertyPreview> propertyPreview;
        internalProperties[i].value->buildPropertyPreview(
            context, internalProperties[i].name, &propertyPreview);
        if (propertyPreview) {
          properties->emplace_back(std::move(propertyPreview));
        }
      }

      getPrivatePropertiesForPreview(context, objectForPreview, nameLimit,
                                     &overflow, properties.get());

      std::vector<PropertyMirror> mirrors;
      if (getPropertiesForPreview(context, objectForPreview, nameLimit,
                                  indexLimit, &overflow, &mirrors)) {
        for (size_t i = 0; i < mirrors.size(); ++i) {
          std::unique_ptr<PropertyPreview> preview;
          std::unique_ptr<ObjectPreview> valuePreview;
          if (mirrors[i].value) {
            mirrors[i].value->buildPropertyPreview(context, mirrors[i].name,
                                                   &preview);
            if (generatePreviewForTable) {
              int tableLimit = 1000;
              mirrors[i].value->buildObjectPreview(context, false, &tableLimit,
                                                   &tableLimit, &valuePreview);
            }
          } else {
            preview = PropertyPreview::create()
                          .setName(mirrors[i].name)
                          .setType(PropertyPreview::TypeEnum::Accessor)
                          .build();
          }
          if (valuePreview) {
            preview->setValuePreview(std::move(valuePreview));
          }
          properties->emplace_back(std::move(preview));
        }
      }

      std::vector<EntryMirror> entries;
      if (EntryMirror::getEntries(context, objectForPreview, 5, &overflow,
                                  &entries)) {
        if (forEntry) {
          overflow = true;
        } else {
          entriesPreview = std::make_unique<protocol::Array<EntryPreview>>();
          for (const auto& entry : entries) {
            std::unique_ptr<ObjectPreview> valuePreview;
            entry.value->buildEntryPreview(context, nameLimit, indexLimit,
                                           &valuePreview);
            if (!valuePreview) continue;
            std::unique_ptr<ObjectPreview> keyPreview;
            if (entry.key) {
              entry.key->buildEntryPreview(context, nameLimit, indexLimit,
                                           &keyPreview);
              if (!keyPreview) continue;
            }
            std::unique_ptr<EntryPreview> entryPreview =
                EntryPreview::create()
                    .setValue(std::move(valuePreview))
                    .build();
            if (keyPreview) entryPreview->setKey(std::move(keyPreview));
            entriesPreview->emplace_back(std::move(entryPreview));
          }
        }
      }
    }
    *result = ObjectPreview::create()
                  .setType(RemoteObject::TypeEnum::Object)
                  .setDescription(m_description)
                  .setOverflow(overflow)
                  .setProperties(std::move(properties))
                  .build();
    if (m_hasSubtype) (*result)->setSubtype(m_subtype);
    if (entriesPreview) (*result)->setEntries(std::move(entriesPreview));
  }

  String16 m_description;
  bool m_hasSubtype;
  String16 m_subtype;
};

void nativeGetterCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Object> data = info.Data().As<v8::Object>();
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Value> name;
  if (!data->GetRealNamedProperty(context, toV8String(isolate, "name"))
           .ToLocal(&name)) {
    return;
  }
  v8::Local<v8::Value> object;
  if (!data->GetRealNamedProperty(context, toV8String(isolate, "object"))
           .ToLocal(&object) ||
      !object->IsObject()) {
    return;
  }
  v8::Local<v8::Value> value;
  if (!object.As<v8::Object>()->Get(context, name).ToLocal(&value)) return;
  info.GetReturnValue().Set(value);
}

std::unique_ptr<ValueMirror> createNativeGetter(v8::Local<v8::Context> context,
                                                v8::Local<v8::Value> object,
                                                v8::Local<v8::Name> name) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::TryCatch tryCatch(isolate);

  v8::Local<v8::Object> data = v8::Object::New(isolate);
  if (data->Set(context, toV8String(isolate, "name"), name).IsNothing()) {
    return nullptr;
  }
  if (data->Set(context, toV8String(isolate, "object"), object).IsNothing()) {
    return nullptr;
  }

  v8::Local<v8::Function> function;
  if (!v8::Function::New(context, nativeGetterCallback, data, 0,
                         v8::ConstructorBehavior::kThrow)
           .ToLocal(&function)) {
    return nullptr;
  }
  return ValueMirror::create(context, function);
}

void nativeSetterCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  if (info.Length() < 1) return;
  v8::Local<v8::Object> data = info.Data().As<v8::Object>();
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Value> name;
  if (!data->GetRealNamedProperty(context, toV8String(isolate, "name"))
           .ToLocal(&name)) {
    return;
  }
  v8::Local<v8::Value> object;
  if (!data->GetRealNamedProperty(context, toV8String(isolate, "object"))
           .ToLocal(&object) ||
      !object->IsObject()) {
    return;
  }
  if (!object.As<v8::Object>()->Set(context, name, info[0]).IsNothing()) return;
}

std::unique_ptr<ValueMirror> createNativeSetter(v8::Local<v8::Context> context,
                                                v8::Local<v8::Value> object,
                                                v8::Local<v8::Name> name) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::TryCatch tryCatch(isolate);

  v8::Local<v8::Object> data = v8::Object::New(isolate);
  if (data->Set(context, toV8String(isolate, "name"), name).IsNothing()) {
    return nullptr;
  }
  if (data->Set(context, toV8String(isolate, "object"), object).IsNothing()) {
    return nullptr;
  }

  v8::Local<v8::Function> function;
  if (!v8::Function::New(context, nativeSetterCallback, data, 1,
                         v8::ConstructorBehavior::kThrow)
           .ToLocal(&function)) {
    return nullptr;
  }
  return ValueMirror::create(context, function);
}

bool doesAttributeHaveObservableSideEffectOnGet(v8::Local<v8::Context> context,
                                                v8::Local<v8::Object> object,
                                                v8::Local<v8::Name> name) {
  // TODO(dgozman): we should remove this, annotate more embedder properties as
  // side-effect free, and call all getters which do not produce side effects.
  if (!name->IsString()) return false;
  v8::Isolate* isolate = context->GetIsolate();
  if (!name.As<v8::String>()->StringEquals(toV8String(isolate, "body"))) {
    return false;
  }

  v8::TryCatch tryCatch(isolate);
  v8::Local<v8::Value> request;
  if (context->Global()
          ->GetRealNamedProperty(context, toV8String(isolate, "Request"))
          .ToLocal(&request)) {
    if (request->IsObject() &&
        object->InstanceOf(context, request.As<v8::Object>())
            .FromMaybe(false)) {
      return true;
    }
  }
  if (tryCatch.HasCaught()) tryCatch.Reset();

  v8::Local<v8::Value> response;
  if (context->Global()
          ->GetRealNamedProperty(context, toV8String(isolate, "Response"))
          .ToLocal(&response)) {
    if (response->IsObject() &&
        object->InstanceOf(context, response.As<v8::Object>())
            .FromMaybe(false)) {
      return true;
    }
  }
  return false;
}

}  // anonymous namespace

ValueMirror::~ValueMirror() = default;

// static
bool ValueMirror::getProperties(v8::Local<v8::Context> context,
                                v8::Local<v8::Object> object,
                                bool ownProperties, bool accessorPropertiesOnly,
                                bool nonIndexedPropertiesOnly,
                                PropertyAccumulator* accumulator) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::TryCatch tryCatch(isolate);
  v8::Local<v8::Set> set = v8::Set::New(isolate);

  v8::MicrotasksScope microtasksScope(context,
                                      v8::MicrotasksScope::kDoNotRunMicrotasks);
  V8InternalValueType internalType = v8InternalValueTypeFrom(context, object);
  if (internalType == V8InternalValueType::kScope) {
    v8::Local<v8::Value> value;
    if (!object->Get(context, toV8String(isolate, "object")).ToLocal(&value) ||
        !value->IsObject()) {
      return false;
    } else {
      object = value.As<v8::Object>();
    }
  }
  if (internalType == V8InternalValueType::kScopeList ||
      internalType == V8InternalValueType::kPrivateMethodList) {
    if (!set->Add(context, toV8String(isolate, "length")).ToLocal(&set)) {
      return false;
    }
  }

  auto iterator = v8::debug::PropertyIterator::Create(context, object,
                                                      nonIndexedPropertiesOnly);
  if (!iterator) {
    CHECK(tryCatch.HasCaught());
    return false;
  }
  while (!iterator->Done()) {
    bool isOwn = iterator->is_own();
    if (!isOwn && ownProperties) break;
    v8::Local<v8::Name> v8Name = iterator->name();
    v8::Maybe<bool> result = set->Has(context, v8Name);
    if (result.IsNothing()) return false;
    if (result.FromJust()) {
      if (!iterator->Advance().FromMaybe(false)) {
        CHECK(tryCatch.HasCaught());
        return false;
      }
      continue;
    }
    if (!set->Add(context, v8Name).ToLocal(&set)) return false;

    String16 name;
    std::unique_ptr<ValueMirror> symbolMirror;
    if (v8Name->IsString()) {
      name = toProtocolString(isolate, v8Name.As<v8::String>());
    } else {
      v8::Local<v8::Symbol> symbol = v8Name.As<v8::Symbol>();
      name = descriptionForSymbol(context, symbol);
      symbolMirror = ValueMirror::create(context, symbol);
    }

    v8::PropertyAttribute attributes;
    std::unique_ptr<ValueMirror> valueMirror;
    std::unique_ptr<ValueMirror> getterMirror;
    std::unique_ptr<ValueMirror> setterMirror;
    std::unique_ptr<ValueMirror> exceptionMirror;
    bool writable = false;
    bool enumerable = false;
    bool configurable = false;

    bool isAccessorProperty = false;
    v8::TryCatch tryCatchAttributes(isolate);
    if (!iterator->attributes().To(&attributes)) {
      exceptionMirror =
          ValueMirror::create(context, tryCatchAttributes.Exception());
    } else {
      if (iterator->is_native_accessor()) {
        if (iterator->has_native_getter()) {
          getterMirror = createNativeGetter(context, object, v8Name);
        }
        if (iterator->has_native_setter()) {
          setterMirror = createNativeSetter(context, object, v8Name);
        }
        writable = !(attributes & v8::PropertyAttribute::ReadOnly);
        enumerable = !(attributes & v8::PropertyAttribute::DontEnum);
        configurable = !(attributes & v8::PropertyAttribute::DontDelete);
        isAccessorProperty = getterMirror || setterMirror;
      } else {
        v8::TryCatch tryCatchDescriptor(isolate);
        v8::debug::PropertyDescriptor descriptor;
        if (!iterator->descriptor().To(&descriptor)) {
          exceptionMirror =
              ValueMirror::create(context, tryCatchDescriptor.Exception());
        } else {
          writable = descriptor.has_writable ? descriptor.writable : false;
          enumerable =
              descriptor.has_enumerable ? descriptor.enumerable : false;
          configurable =
              descriptor.has_configurable ? descriptor.configurable : false;
          if (!descriptor.value.IsEmpty()) {
            valueMirror = ValueMirror::create(context, descriptor.value);
          }
          v8::Local<v8::Function> getterFunction;
          if (!descriptor.get.IsEmpty()) {
            v8::Local<v8::Value> get = descriptor.get;
            getterMirror = ValueMirror::create(context, get);
            if (get->IsFunction()) getterFunction = get.As<v8::Function>();
          }
          if (!descriptor.set.IsEmpty()) {
            setterMirror = ValueMirror::create(context, descriptor.set);
          }
          isAccessorProperty = getterMirror || setterMirror;
          if (name != "__proto__" && !getterFunction.IsEmpty() &&
              getterFunction->ScriptId() == v8::UnboundScript::kNoScriptId &&
              !doesAttributeHaveObservableSideEffectOnGet(context, object,
                                                          v8Name)) {
            v8::TryCatch tryCatchFunction(isolate);
            v8::Local<v8::Value> value;
            if (object->Get(context, v8Name).ToLocal(&value)) {
              if (value->IsPromise() &&
                  value.As<v8::Promise>()->State() == v8::Promise::kRejected) {
                value.As<v8::Promise>()->MarkAsHandled();
              } else {
                valueMirror = ValueMirror::create(context, value);
                setterMirror = nullptr;
                getterMirror = nullptr;
              }
            }
          }
        }
      }
    }
    if (accessorPropertiesOnly && !isAccessorProperty) continue;
    auto mirror = PropertyMirror{name,
                                 writable,
                                 configurable,
                                 enumerable,
                                 isOwn,
                                 iterator->is_array_index(),
                                 isAccessorProperty && valueMirror,
                                 std::move(valueMirror),
                                 std::move(getterMirror),
                                 std::move(setterMirror),
                                 std::move(symbolMirror),
                                 std::move(exceptionMirror)};
    if (!accumulator->Add(std::move(mirror))) return true;

    if (!iterator->Advance().FromMaybe(false)) {
      CHECK(tryCatchAttributes.HasCaught());
      return false;
    }
  }
  return true;
}

// static
void ValueMirror::getInternalProperties(
    v8::Local<v8::Context> context, v8::Local<v8::Object> object,
    std::vector<InternalPropertyMirror>* mirrors) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::MicrotasksScope microtasksScope(context,
                                      v8::MicrotasksScope::kDoNotRunMicrotasks);
  v8::TryCatch tryCatch(isolate);
  if (object->IsFunction()) {
    v8::Local<v8::Function> function = object.As<v8::Function>();
    auto location = LocationMirror::create(function);
    if (location) {
      mirrors->emplace_back(InternalPropertyMirror{
          String16("[[FunctionLocation]]"), std::move(location)});
    }
    if (function->IsGeneratorFunction()) {
      mirrors->emplace_back(InternalPropertyMirror{
          String16("[[IsGenerator]]"),
          ValueMirror::create(context, v8::True(context->GetIsolate()))});
    }
  }
  if (object->IsGeneratorObject()) {
    auto location = LocationMirror::createForGenerator(object);
    if (location) {
      mirrors->emplace_back(InternalPropertyMirror{
          String16("[[GeneratorLocation]]"), std::move(location)});
    }
  }
  V8Debugger* debugger =
      static_cast<V8InspectorImpl*>(v8::debug::GetInspector(isolate))
          ->debugger();
  v8::Local<v8::Array> properties;
  if (debugger->internalProperties(context, object).ToLocal(&properties)) {
    for (uint32_t i = 0; i < properties->Length(); i += 2) {
      v8::Local<v8::Value> name;
      if (!properties->Get(context, i).ToLocal(&name) || !name->IsString()) {
        tryCatch.Reset();
        continue;
      }
      v8::Local<v8::Value> value;
      if (!properties->Get(context, i + 1).ToLocal(&value)) {
        tryCatch.Reset();
        continue;
      }
      auto wrapper = ValueMirror::create(context, value);
      if (wrapper) {
        mirrors->emplace_back(InternalPropertyMirror{
            toProtocolStringWithTypeCheck(context->GetIsolate(), name),
            std::move(wrapper)});
      }
    }
  }
}

// static
std::vector<PrivatePropertyMirror> ValueMirror::getPrivateProperties(
    v8::Local<v8::Context> context, v8::Local<v8::Object> object,
    bool accessorPropertiesOnly) {
  std::vector<PrivatePropertyMirror> mirrors;
  v8::Isolate* isolate = context->GetIsolate();
  v8::MicrotasksScope microtasksScope(context,
                                      v8::MicrotasksScope::kDoNotRunMicrotasks);
  v8::TryCatch tryCatch(isolate);

  v8::LocalVector<v8::Value> names(isolate);
  v8::LocalVector<v
"""


```