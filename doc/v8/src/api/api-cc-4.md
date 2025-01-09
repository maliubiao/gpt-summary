Response:
The user wants a summary of the functionalities present in the provided C++ code snippet from `v8/src/api/api.cc`. I need to analyze the code and identify the main features it implements.

Here's a breakdown of the code's functionality:

1. **Error and Stack Trace Handling:** The code defines methods for getting information about errors (Message class) and stack traces (StackTrace and StackFrame classes). This includes retrieving source code lines, script names, function names, and locations within the code.

2. **JSON Parsing and Stringification:** The `JSON` class provides static methods for parsing JSON strings into V8 values and stringifying V8 values back into JSON strings.

3. **Value Serialization and Deserialization:** The `ValueSerializer` and `ValueDeserializer` classes are responsible for converting V8 values into a byte stream and reconstructing V8 values from a byte stream, respectively. This includes handling various types like objects, array buffers, and WASM modules.

4. **Value Type Checking:**  The `Value` class has a large number of methods (e.g., `IsUndefined`, `IsString`, `IsArray`) to determine the specific type of a V8 value.

5. **Value Conversion:**  The `Value` class also offers methods for converting V8 values to different types (e.g., `ToString`, `ToNumber`, `ToBoolean`).

6. **Type Casting Assertions:** The code includes `CheckCast` functions for various V8 API types, which are used to verify the type of a given `Data` object at runtime.

Based on this analysis, I can now formulate a summary addressing all the user's constraints.
这是目录为v8/src/api/api.cc的一个v8源代码片段，它主要负责实现 V8 JavaScript 引擎的 **C++ API 中与错误信息、堆栈跟踪、JSON 处理、值的序列化与反序列化以及值类型判断和转换相关的接口**。

**功能归纳：**

1. **错误信息 (Message):**
   - 提供获取错误消息的各种属性的方法，例如错误源、错误所在行号、列号、脚本资源名称等。
   - 可以获取包含错误代码行的源代码片段。

2. **堆栈跟踪 (StackTrace, StackFrame):**
   - 允许获取当前 JavaScript 执行的堆栈信息。
   - 可以获取堆栈中每个帧的详细信息，例如脚本 ID、脚本名称、函数名称、代码位置（行号和列号）、是否是 eval 代码、是否是构造函数、是否是 WebAssembly 代码等。

3. **JSON 处理 (JSON):**
   - 提供了 `Parse` 方法用于将 JSON 字符串解析为 V8 的 Value 对象。
   - 提供了 `Stringify` 方法用于将 V8 的 Value 对象转换为 JSON 字符串。

4. **值的序列化与反序列化 (ValueSerializer, ValueDeserializer):**
   - `ValueSerializer` 负责将 V8 的 Value 对象序列化为字节流，用于存储或传输。
   - `ValueDeserializer` 负责将字节流反序列化为 V8 的 Value 对象。
   - 支持处理各种类型的对象，包括 ArrayBuffer、SharedArrayBuffer 和 WebAssembly 模块。

5. **值类型判断 (Value::Is\*):**
   - 提供了大量的 `Is...` 方法用于判断 Value 对象的具体类型，例如 `IsUndefined`、`IsString`、`IsArray`、`IsObject`、`IsNumber` 等等。

6. **值类型转换 (Value::To\*):**
   - 提供了 `To...` 方法用于将 Value 对象转换为其他类型，例如 `ToString`、`ToNumber`、`ToBoolean`、`ToObject` 等。

7. **类型安全检查 (CheckCast):**
   - 提供了一系列的 `CheckCast` 函数，用于在 C++ 代码中进行类型断言，确保 Value 指针指向的是预期的类型，避免类型错误。

**关于 .tq 结尾：**

如果 `v8/src/api/api.cc` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码**。但根据你提供的文件名，它是 `.cc` 结尾，所以这是一个 **C++ 源代码文件**。

**与 JavaScript 的关系及举例：**

这个 C++ 代码片段提供的功能，在 JavaScript 中可以通过内置的对象和方法来访问和使用。

**1. 错误信息和堆栈跟踪：**

```javascript
try {
  undefinedFunction(); // 故意引发错误
} catch (e) {
  console.error("错误信息:", e.message);
  console.error("堆栈跟踪:", e.stack);
}
```

在上面的 JavaScript 代码中，`e.message` 对应 `Message::Get()` 等方法获取的信息，`e.stack` 字符串则包含了堆栈跟踪信息，与 `StackTrace` 和 `StackFrame` 类提供的功能对应。

**2. JSON 处理：**

```javascript
const jsonString = '{"name": "张三", "age": 30}';
const jsonObject = JSON.parse(jsonString);
console.log(jsonObject.name); // 输出: 张三

const jsObject = { city: "北京" };
const jsonOutput = JSON.stringify(jsObject);
console.log(jsonOutput); // 输出: {"city":"北京"}
```

这里的 `JSON.parse()` 对应 `JSON::Parse()`，`JSON.stringify()` 对应 `JSON::Stringify()`。

**3. 值的序列化与反序列化 (间接关系)：**

JavaScript 中没有直接对应的序列化/反序列化 API 与 `ValueSerializer` 和 `ValueDeserializer` 完全一致。但是，一些 API，例如 `structuredClone()` (实验性) 以及某些 Web API 中使用的序列化机制，其底层可能使用了类似的技术。

**4. 值类型判断：**

```javascript
const value = 123;
console.log(typeof value === 'number'); // 输出: true

const arr = [];
console.log(Array.isArray(arr)); // 输出: true
```

JavaScript 的 `typeof` 运算符和 `Array.isArray()` 等方法与 C++ 中的 `Value::IsNumber()`、`Value::IsArray()` 等方法的功能类似。

**5. 值类型转换：**

```javascript
const numStr = "456";
const num = Number(numStr);
console.log(typeof num); // 输出: number

const boolValue = !!0;
console.log(boolValue); // 输出: false
```

JavaScript 的 `Number()`、`String()`、`Boolean()` 等构造函数以及一些隐式类型转换机制，与 C++ 中的 `Value::ToNumber()`、`Value::ToString()`、`Value::ToBoolean()` 等方法功能对应。

**代码逻辑推理及假设输入输出：**

**假设输入：** 一个指向 `Message` 对象的 C++ 指针 `message_ptr`，该消息表示一个 JavaScript 运行时错误，发生在 `script.js` 文件的第 10 行，第 5 列，错误消息为 "TypeError: Cannot read property 'x' of undefined"。

**输出：**

- `Message::Get()` 可能返回一个 V8 String 对象，其内容转换为 C++ 字符串为 "TypeError: Cannot read property 'x' of undefined"。
- `Message::GetLineNumber()` 返回 10。
- `Message::GetStartColumn()` 返回 5。
- `Message::GetScriptName()` 可能返回一个 V8 String 对象，其内容转换为 C++ 字符串为 "script.js"。
- `Message::GetSourceLine()` 可能返回一个 V8 String 对象，包含 `script.js` 第 10 行的源代码。

**用户常见的编程错误示例：**

1. **错误地假设值的类型：**

   ```javascript
   function processValue(value) {
     // 错误地假设 value 一定是字符串
     console.log(value.toUpperCase());
   }

   processValue(123); // 会导致错误，因为数字没有 toUpperCase 方法
   ```

   V8 的 C++ API 提供了类型检查方法，可以帮助开发者在 C++ 层面更安全地处理 JavaScript 值。

2. **JSON 解析错误：**

   ```javascript
   const invalidJSON = "{name: 'John',}"; // 缺少引号
   try {
     const obj = JSON.parse(invalidJSON);
     console.log(obj.name);
   } catch (e) {
     console.error("JSON 解析失败:", e.message);
   }
   ```

   V8 的 `JSON::Parse()` 方法在解析失败时会抛出异常，C++ 代码需要妥善处理这些异常。

**总结：**

这段 `v8/src/api/api.cc` 的代码是 V8 引擎 C++ API 的核心组成部分，它提供了与 JavaScript 运行时的错误处理、堆栈跟踪、数据交换（JSON）、数据持久化（序列化/反序列化）以及类型系统交互的关键接口。这些接口使得 C++ 代码能够深入地与 V8 引擎集成，并对 JavaScript 代码的执行进行更精细的控制和分析。

Prompt: 
```
这是目录为v8/src/api/api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共15部分，请归纳一下它的功能

"""

  RETURN_ESCAPED(
      Utils::ToLocal(i::direct_handle(self->GetSource(), i_isolate)));
}

MaybeLocal<String> Message::GetSourceLine(Local<Context> context) const {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  InternalEscapableScope handle_scope(i_isolate);
  i::JSMessageObject::EnsureSourcePositionsAvailable(i_isolate, self);
  RETURN_ESCAPED(Utils::ToLocal(self->GetSourceLine()));
}

void Message::PrintCurrentStackTrace(Isolate* v8_isolate, std::ostream& out) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i_isolate->PrintCurrentStackTrace(out);
}

// --- S t a c k T r a c e ---

int StackTrace::GetID() const {
  auto self = Utils::OpenHandle(this);
  return self->id();
}

Local<StackFrame> StackTrace::GetFrame(Isolate* v8_isolate,
                                       uint32_t index) const {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  return Utils::StackFrameToLocal(
      i::direct_handle(self->get(index), i_isolate));
}

int StackTrace::GetFrameCount() const {
  auto self = Utils::OpenHandle(this);
  return self->length();
}

Local<StackTrace> StackTrace::CurrentStackTrace(Isolate* v8_isolate,
                                                int frame_limit,
                                                StackTraceOptions options) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::StackTraceInfo> stack_trace =
      i_isolate->CaptureDetailedStackTrace(frame_limit, options);
  return Utils::StackTraceToLocal(stack_trace);
}

Local<String> StackTrace::CurrentScriptNameOrSourceURL(Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::String> name_or_source_url =
      i_isolate->CurrentScriptNameOrSourceURL();
  return Utils::ToLocal(name_or_source_url);
}

// --- S t a c k F r a m e ---

Location StackFrame::GetLocation() const {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  i::DirectHandle<i::Script> script(self->script(), i_isolate);
  i::Script::PositionInfo info;
  CHECK(i::Script::GetPositionInfo(
      script, i::StackFrameInfo::GetSourcePosition(self), &info));
  if (script->HasSourceURLComment()) {
    info.line -= script->line_offset();
    if (info.line == 0) {
      info.column -= script->column_offset();
    }
  }
  return {info.line, info.column};
}

int StackFrame::GetScriptId() const {
  return Utils::OpenDirectHandle(this)->script()->id();
}

Local<String> StackFrame::GetScriptName() const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  i::DirectHandle<i::Object> name(self->script()->name(), i_isolate);
  if (!IsString(*name)) return {};
  return Utils::ToLocal(i::Cast<i::String>(name));
}

Local<String> StackFrame::GetScriptNameOrSourceURL() const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  i::DirectHandle<i::Object> name_or_source_url(
      self->script()->GetNameOrSourceURL(), i_isolate);
  if (!IsString(*name_or_source_url)) return {};
  return Utils::ToLocal(i::Cast<i::String>(name_or_source_url));
}

Local<String> StackFrame::GetScriptSource() const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  if (!self->script()->HasValidSource()) return {};
  i::DirectHandle<i::PrimitiveHeapObject> source(self->script()->source(),
                                                 i_isolate);
  if (!IsString(*source)) return {};
  return Utils::ToLocal(i::Cast<i::String>(source));
}

Local<String> StackFrame::GetScriptSourceMappingURL() const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  i::DirectHandle<i::Object> source_mapping_url(
      self->script()->source_mapping_url(), i_isolate);
  if (!IsString(*source_mapping_url)) return {};
  return Utils::ToLocal(i::Cast<i::String>(source_mapping_url));
}

Local<String> StackFrame::GetFunctionName() const {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  i::DirectHandle<i::String> name(self->function_name(), i_isolate);
  if (name->length() == 0) return {};
  return Utils::ToLocal(name);
}

bool StackFrame::IsEval() const {
  auto self = Utils::OpenDirectHandle(this);
  return self->script()->compilation_type() ==
         i::Script::CompilationType::kEval;
}

bool StackFrame::IsConstructor() const {
  return Utils::OpenDirectHandle(this)->is_constructor();
}

bool StackFrame::IsWasm() const { return !IsUserJavaScript(); }

bool StackFrame::IsUserJavaScript() const {
  return Utils::OpenDirectHandle(this)->script()->IsUserJavaScript();
}

// --- J S O N ---

MaybeLocal<Value> JSON::Parse(Local<Context> context,
                              Local<String> json_string) {
  PREPARE_FOR_EXECUTION(context, JSON, Parse);
  auto string = Utils::OpenHandle(*json_string);
  i::Handle<i::String> source = i::String::Flatten(i_isolate, string);
  i::Handle<i::Object> undefined = i_isolate->factory()->undefined_value();
  auto maybe =
      source->IsOneByteRepresentation()
          ? i::JsonParser<uint8_t>::Parse(i_isolate, source, undefined)
          : i::JsonParser<uint16_t>::Parse(i_isolate, source, undefined);
  Local<Value> result;
  has_exception = !ToLocal<Value>(maybe, &result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(result);
}

MaybeLocal<String> JSON::Stringify(Local<Context> context,
                                   Local<Value> json_object,
                                   Local<String> gap) {
  PREPARE_FOR_EXECUTION(context, JSON, Stringify);
  i::Handle<i::JSAny> object;
  if (!Utils::ApiCheck(
          i::TryCast<i::JSAny>(Utils::OpenHandle(*json_object), &object),
          "JSON::Stringify",
          "Invalid object, must be a JSON-serializable object.")) {
    return {};
  }
  i::Handle<i::Undefined> replacer = i_isolate->factory()->undefined_value();
  i::Handle<i::String> gap_string = gap.IsEmpty()
                                        ? i_isolate->factory()->empty_string()
                                        : Utils::OpenHandle(*gap);
  i::Handle<i::Object> maybe;
  has_exception = !i::JsonStringify(i_isolate, object, replacer, gap_string)
                       .ToHandle(&maybe);
  RETURN_ON_FAILED_EXECUTION(String);
  Local<String> result;
  has_exception =
      !ToLocal<String>(i::Object::ToString(i_isolate, maybe), &result);
  RETURN_ON_FAILED_EXECUTION(String);
  RETURN_ESCAPED(result);
}

// --- V a l u e   S e r i a l i z a t i o n ---

SharedValueConveyor::SharedValueConveyor(SharedValueConveyor&& other) noexcept
    : private_(std::move(other.private_)) {}

SharedValueConveyor::~SharedValueConveyor() = default;

SharedValueConveyor& SharedValueConveyor::operator=(
    SharedValueConveyor&& other) noexcept {
  private_ = std::move(other.private_);
  return *this;
}

SharedValueConveyor::SharedValueConveyor(Isolate* v8_isolate)
    : private_(std::make_unique<i::SharedObjectConveyorHandles>(
          reinterpret_cast<i::Isolate*>(v8_isolate))) {}

Maybe<bool> ValueSerializer::Delegate::WriteHostObject(Isolate* v8_isolate,
                                                       Local<Object> object) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  THROW_NEW_ERROR_RETURN_VALUE(
      i_isolate,
      NewError(i_isolate->error_function(), i::MessageTemplate::kDataCloneError,
               Utils::OpenHandle(*object)),
      Nothing<bool>());
}

bool ValueSerializer::Delegate::HasCustomHostObject(Isolate* v8_isolate) {
  return false;
}

Maybe<bool> ValueSerializer::Delegate::IsHostObject(Isolate* v8_isolate,
                                                    Local<Object> object) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  auto js_object = i::Cast<i::JSObject>(Utils::OpenDirectHandle(*object));
  return Just<bool>(
      i::JSObject::GetEmbedderFieldCount(js_object->map(i_isolate)));
}

Maybe<uint32_t> ValueSerializer::Delegate::GetSharedArrayBufferId(
    Isolate* v8_isolate, Local<SharedArrayBuffer> shared_array_buffer) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i_isolate->Throw(*i_isolate->factory()->NewError(
      i_isolate->error_function(), i::MessageTemplate::kDataCloneError,
      Utils::OpenHandle(*shared_array_buffer)));
  return Nothing<uint32_t>();
}

Maybe<uint32_t> ValueSerializer::Delegate::GetWasmModuleTransferId(
    Isolate* v8_isolate, Local<WasmModuleObject> module) {
  return Nothing<uint32_t>();
}

bool ValueSerializer::Delegate::AdoptSharedValueConveyor(
    Isolate* v8_isolate, SharedValueConveyor&& conveyor) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i_isolate->Throw(*i_isolate->factory()->NewError(
      i_isolate->error_function(), i::MessageTemplate::kDataCloneError,
      i_isolate->factory()->NewStringFromAsciiChecked("shared value")));
  return false;
}

void* ValueSerializer::Delegate::ReallocateBufferMemory(void* old_buffer,
                                                        size_t size,
                                                        size_t* actual_size) {
  *actual_size = size;
  return base::Realloc(old_buffer, size);
}

void ValueSerializer::Delegate::FreeBufferMemory(void* buffer) {
  return base::Free(buffer);
}

struct ValueSerializer::PrivateData {
  explicit PrivateData(i::Isolate* i, ValueSerializer::Delegate* delegate)
      : isolate(i), serializer(i, delegate) {}
  i::Isolate* isolate;
  i::ValueSerializer serializer;
};

ValueSerializer::ValueSerializer(Isolate* v8_isolate)
    : ValueSerializer(v8_isolate, nullptr) {}

ValueSerializer::ValueSerializer(Isolate* v8_isolate, Delegate* delegate)
    : private_(new PrivateData(reinterpret_cast<i::Isolate*>(v8_isolate),
                               delegate)) {}

ValueSerializer::~ValueSerializer() { delete private_; }

void ValueSerializer::WriteHeader() { private_->serializer.WriteHeader(); }

void ValueSerializer::SetTreatArrayBufferViewsAsHostObjects(bool mode) {
  private_->serializer.SetTreatArrayBufferViewsAsHostObjects(mode);
}

Maybe<bool> ValueSerializer::WriteValue(Local<Context> context,
                                        Local<Value> value) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, ValueSerializer, WriteValue, i::HandleScope);
  auto object = Utils::OpenHandle(*value);
  Maybe<bool> result = private_->serializer.WriteObject(object);
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return result;
}

std::pair<uint8_t*, size_t> ValueSerializer::Release() {
  return private_->serializer.Release();
}

void ValueSerializer::TransferArrayBuffer(uint32_t transfer_id,
                                          Local<ArrayBuffer> array_buffer) {
  private_->serializer.TransferArrayBuffer(transfer_id,
                                           Utils::OpenHandle(*array_buffer));
}

void ValueSerializer::WriteUint32(uint32_t value) {
  private_->serializer.WriteUint32(value);
}

void ValueSerializer::WriteUint64(uint64_t value) {
  private_->serializer.WriteUint64(value);
}

void ValueSerializer::WriteDouble(double value) {
  private_->serializer.WriteDouble(value);
}

void ValueSerializer::WriteRawBytes(const void* source, size_t length) {
  private_->serializer.WriteRawBytes(source, length);
}

MaybeLocal<Object> ValueDeserializer::Delegate::ReadHostObject(
    Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i_isolate->Throw(*i_isolate->factory()->NewError(
      i_isolate->error_function(),
      i::MessageTemplate::kDataCloneDeserializationError));
  return MaybeLocal<Object>();
}

MaybeLocal<WasmModuleObject> ValueDeserializer::Delegate::GetWasmModuleFromId(
    Isolate* v8_isolate, uint32_t id) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i_isolate->Throw(*i_isolate->factory()->NewError(
      i_isolate->error_function(),
      i::MessageTemplate::kDataCloneDeserializationError));
  return MaybeLocal<WasmModuleObject>();
}

MaybeLocal<SharedArrayBuffer>
ValueDeserializer::Delegate::GetSharedArrayBufferFromId(Isolate* v8_isolate,
                                                        uint32_t id) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i_isolate->Throw(*i_isolate->factory()->NewError(
      i_isolate->error_function(),
      i::MessageTemplate::kDataCloneDeserializationError));
  return MaybeLocal<SharedArrayBuffer>();
}

const SharedValueConveyor* ValueDeserializer::Delegate::GetSharedValueConveyor(
    Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i_isolate->Throw(*i_isolate->factory()->NewError(
      i_isolate->error_function(),
      i::MessageTemplate::kDataCloneDeserializationError));
  return nullptr;
}

struct ValueDeserializer::PrivateData {
  PrivateData(i::Isolate* i_isolate, base::Vector<const uint8_t> data,
              Delegate* delegate)
      : isolate(i_isolate), deserializer(i_isolate, data, delegate) {}
  i::Isolate* isolate;
  i::ValueDeserializer deserializer;
  bool supports_legacy_wire_format = false;
};

ValueDeserializer::ValueDeserializer(Isolate* v8_isolate, const uint8_t* data,
                                     size_t size)
    : ValueDeserializer(v8_isolate, data, size, nullptr) {}

ValueDeserializer::ValueDeserializer(Isolate* v8_isolate, const uint8_t* data,
                                     size_t size, Delegate* delegate) {
  private_ = new PrivateData(reinterpret_cast<i::Isolate*>(v8_isolate),
                             base::Vector<const uint8_t>(data, size), delegate);
}

ValueDeserializer::~ValueDeserializer() { delete private_; }

Maybe<bool> ValueDeserializer::ReadHeader(Local<Context> context) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8_NO_SCRIPT(i_isolate, context, ValueDeserializer, ReadHeader,
                     i::HandleScope);

  bool read_header = false;
  has_exception = !private_->deserializer.ReadHeader().To(&read_header);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  DCHECK(read_header);

  static const uint32_t kMinimumNonLegacyVersion = 13;
  if (GetWireFormatVersion() < kMinimumNonLegacyVersion &&
      !private_->supports_legacy_wire_format) {
    i_isolate->Throw(*i_isolate->factory()->NewError(
        i::MessageTemplate::kDataCloneDeserializationVersionError));
    has_exception = true;
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  }

  return Just(true);
}

void ValueDeserializer::SetSupportsLegacyWireFormat(
    bool supports_legacy_wire_format) {
  private_->supports_legacy_wire_format = supports_legacy_wire_format;
}

uint32_t ValueDeserializer::GetWireFormatVersion() const {
  return private_->deserializer.GetWireFormatVersion();
}

MaybeLocal<Value> ValueDeserializer::ReadValue(Local<Context> context) {
  PREPARE_FOR_EXECUTION(context, ValueDeserializer, ReadValue);
  i::MaybeHandle<i::Object> result;
  if (GetWireFormatVersion() > 0) {
    result = private_->deserializer.ReadObjectWrapper();
  } else {
    result =
        private_->deserializer.ReadObjectUsingEntireBufferForLegacyFormat();
  }
  Local<Value> value;
  has_exception = !ToLocal(result, &value);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(value);
}

void ValueDeserializer::TransferArrayBuffer(uint32_t transfer_id,
                                            Local<ArrayBuffer> array_buffer) {
  private_->deserializer.TransferArrayBuffer(transfer_id,
                                             Utils::OpenHandle(*array_buffer));
}

void ValueDeserializer::TransferSharedArrayBuffer(
    uint32_t transfer_id, Local<SharedArrayBuffer> shared_array_buffer) {
  private_->deserializer.TransferArrayBuffer(
      transfer_id, Utils::OpenHandle(*shared_array_buffer));
}

bool ValueDeserializer::ReadUint32(uint32_t* value) {
  return private_->deserializer.ReadUint32(value);
}

bool ValueDeserializer::ReadUint64(uint64_t* value) {
  return private_->deserializer.ReadUint64(value);
}

bool ValueDeserializer::ReadDouble(double* value) {
  return private_->deserializer.ReadDouble(value);
}

bool ValueDeserializer::ReadRawBytes(size_t length, const void** data) {
  return private_->deserializer.ReadRawBytes(length, data);
}

// --- D a t a ---

bool Value::FullIsUndefined() const {
  bool result = i::IsUndefined(*Utils::OpenDirectHandle(this));
  DCHECK_EQ(result, QuickIsUndefined());
  return result;
}

bool Value::FullIsNull() const {
  bool result = i::IsNull(*Utils::OpenDirectHandle(this));
  DCHECK_EQ(result, QuickIsNull());
  return result;
}

bool Value::FullIsTrue() const {
  auto object = *Utils::OpenDirectHandle(this);
  if (i::IsSmi(object)) return false;
  return i::IsTrue(object);
}

bool Value::FullIsFalse() const {
  i::Tagged<i::Object> object = *Utils::OpenDirectHandle(this);
  if (i::IsSmi(object)) return false;
  return i::IsFalse(object);
}

bool Value::IsFunction() const {
  return IsCallable(*Utils::OpenDirectHandle(this));
}

bool Value::IsName() const { return i::IsName(*Utils::OpenDirectHandle(this)); }

bool Value::FullIsString() const {
  bool result = i::IsString(*Utils::OpenDirectHandle(this));
  DCHECK_EQ(result, QuickIsString());
  return result;
}

bool Value::IsSymbol() const {
  return IsPublicSymbol(*Utils::OpenDirectHandle(this));
}

bool Value::IsArray() const {
  return IsJSArray(*Utils::OpenDirectHandle(this));
}

bool Value::IsArrayBuffer() const {
  auto obj = *Utils::OpenDirectHandle(this);
  if (!IsJSArrayBuffer(obj)) return false;
  return !i::Cast<i::JSArrayBuffer>(obj)->is_shared();
}

bool Value::IsArrayBufferView() const {
  return IsJSArrayBufferView(*Utils::OpenDirectHandle(this));
}

bool Value::IsTypedArray() const {
  return IsJSTypedArray(*Utils::OpenDirectHandle(this));
}

#define VALUE_IS_TYPED_ARRAY(Type, typeName, TYPE, ctype)                      \
  bool Value::Is##Type##Array() const {                                        \
    auto obj = *Utils::OpenDirectHandle(this);                                 \
    return i::IsJSTypedArray(obj) &&                                           \
           i::Cast<i::JSTypedArray>(obj)->type() == i::kExternal##Type##Array; \
  }

TYPED_ARRAYS_BASE(VALUE_IS_TYPED_ARRAY)
#undef VALUE_IS_TYPED_ARRAY

bool Value::IsFloat16Array() const {
  auto obj = *Utils::OpenDirectHandle(this);
  return i::IsJSTypedArray(obj) &&
         i::Cast<i::JSTypedArray>(obj)->type() == i::kExternalFloat16Array &&
         Utils::ApiCheck(i::v8_flags.js_float16array, "Value::IsFloat16Array",
                         "Float16Array is not supported");
}

bool Value::IsDataView() const {
  auto obj = *Utils::OpenDirectHandle(this);
  return IsJSDataView(obj) || IsJSRabGsabDataView(obj);
}

bool Value::IsSharedArrayBuffer() const {
  auto obj = *Utils::OpenDirectHandle(this);
  if (!IsJSArrayBuffer(obj)) return false;
  return i::Cast<i::JSArrayBuffer>(obj)->is_shared();
}

bool Value::IsObject() const {
  return i::IsJSReceiver(*Utils::OpenDirectHandle(this));
}

bool Value::IsNumber() const {
  return i::IsNumber(*Utils::OpenDirectHandle(this));
}

bool Value::IsBigInt() const {
  return i::IsBigInt(*Utils::OpenDirectHandle(this));
}

bool Value::IsProxy() const {
  return i::IsJSProxy(*Utils::OpenDirectHandle(this));
}

#define VALUE_IS_SPECIFIC_TYPE(Type, Check)              \
  bool Value::Is##Type() const {                         \
    return i::Is##Check(*Utils::OpenDirectHandle(this)); \
  }

VALUE_IS_SPECIFIC_TYPE(ArgumentsObject, JSArgumentsObject)
VALUE_IS_SPECIFIC_TYPE(BigIntObject, BigIntWrapper)
VALUE_IS_SPECIFIC_TYPE(BooleanObject, BooleanWrapper)
VALUE_IS_SPECIFIC_TYPE(NumberObject, NumberWrapper)
VALUE_IS_SPECIFIC_TYPE(StringObject, StringWrapper)
VALUE_IS_SPECIFIC_TYPE(SymbolObject, SymbolWrapper)
VALUE_IS_SPECIFIC_TYPE(Date, JSDate)
VALUE_IS_SPECIFIC_TYPE(Map, JSMap)
VALUE_IS_SPECIFIC_TYPE(Set, JSSet)
#if V8_ENABLE_WEBASSEMBLY
VALUE_IS_SPECIFIC_TYPE(WasmMemoryObject, WasmMemoryObject)
VALUE_IS_SPECIFIC_TYPE(WasmModuleObject, WasmModuleObject)
VALUE_IS_SPECIFIC_TYPE(WasmNull, WasmNull)
#else
bool Value::IsWasmMemoryObject() const { return false; }
bool Value::IsWasmModuleObject() const { return false; }
bool Value::IsWasmNull() const { return false; }
#endif  // V8_ENABLE_WEBASSEMBLY
VALUE_IS_SPECIFIC_TYPE(WeakMap, JSWeakMap)
VALUE_IS_SPECIFIC_TYPE(WeakSet, JSWeakSet)
VALUE_IS_SPECIFIC_TYPE(WeakRef, JSWeakRef)

#undef VALUE_IS_SPECIFIC_TYPE

bool Value::IsBoolean() const {
  return i::IsBoolean(*Utils::OpenDirectHandle(this));
}

bool Value::IsExternal() const {
  i::Tagged<i::Object> obj = *Utils::OpenDirectHandle(this);
  return IsJSExternalObject(obj);
}

bool Value::IsInt32() const {
  i::Tagged<i::Object> obj = *Utils::OpenDirectHandle(this);
  if (i::IsSmi(obj)) return true;
  if (i::IsNumber(obj)) {
    return i::IsInt32Double(i::Object::NumberValue(i::Cast<i::Number>(obj)));
  }
  return false;
}

bool Value::IsUint32() const {
  auto obj = *Utils::OpenDirectHandle(this);
  if (i::IsSmi(obj)) return i::Smi::ToInt(obj) >= 0;
  if (i::IsNumber(obj)) {
    double value = i::Object::NumberValue(i::Cast<i::Number>(obj));
    return !i::IsMinusZero(value) && value >= 0 && value <= i::kMaxUInt32 &&
           value == i::FastUI2D(i::FastD2UI(value));
  }
  return false;
}

bool Value::IsNativeError() const {
  return IsJSError(*Utils::OpenDirectHandle(this));
}

bool Value::IsRegExp() const {
  return IsJSRegExp(*Utils::OpenDirectHandle(this));
}

bool Value::IsAsyncFunction() const {
  auto obj = *Utils::OpenDirectHandle(this);
  if (!IsJSFunction(obj)) return false;
  auto func = i::Cast<i::JSFunction>(obj);
  return i::IsAsyncFunction(func->shared()->kind());
}

bool Value::IsGeneratorFunction() const {
  auto obj = *Utils::OpenDirectHandle(this);
  if (!IsJSFunction(obj)) return false;
  auto func = i::Cast<i::JSFunction>(obj);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(func->GetIsolate());
  return i::IsGeneratorFunction(func->shared()->kind());
}

bool Value::IsGeneratorObject() const {
  return IsJSGeneratorObject(*Utils::OpenDirectHandle(this));
}

bool Value::IsMapIterator() const {
  return IsJSMapIterator(*Utils::OpenDirectHandle(this));
}

bool Value::IsSetIterator() const {
  return IsJSSetIterator(*Utils::OpenDirectHandle(this));
}

bool Value::IsPromise() const {
  return IsJSPromise(*Utils::OpenDirectHandle(this));
}

bool Value::IsModuleNamespaceObject() const {
  return IsJSModuleNamespace(*Utils::OpenDirectHandle(this));
}

MaybeLocal<String> Value::ToString(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsString(*obj)) return ToApiHandle<String>(obj);
  PREPARE_FOR_EXECUTION(context, Object, ToString);
  Local<String> result;
  has_exception =
      !ToLocal<String>(i::Object::ToString(i_isolate, obj), &result);
  RETURN_ON_FAILED_EXECUTION(String);
  RETURN_ESCAPED(result);
}

MaybeLocal<String> Value::ToDetailString(Local<Context> context) const {
  i::DirectHandle<i::Object> obj = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate;
  if (!context.IsEmpty()) {
    i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  } else if (IsSmi(*obj) || !i::GetIsolateFromHeapObject(
                                i::Cast<i::HeapObject>(*obj), &i_isolate)) {
    i_isolate = i::Isolate::Current();
  }
  if (i::IsString(*obj)) return ToApiHandle<String>(obj);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return Utils::ToLocal(i::Object::NoSideEffectsToString(i_isolate, obj));
}

MaybeLocal<Object> Value::ToObject(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsJSReceiver(*obj)) return ToApiHandle<Object>(obj);
  PREPARE_FOR_EXECUTION(context, Object, ToObject);
  Local<Object> result;
  has_exception =
      !ToLocal<Object>(i::Object::ToObject(i_isolate, obj), &result);
  RETURN_ON_FAILED_EXECUTION(Object);
  RETURN_ESCAPED(result);
}

MaybeLocal<BigInt> Value::ToBigInt(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsBigInt(*obj)) return ToApiHandle<BigInt>(obj);
  PREPARE_FOR_EXECUTION(context, Object, ToBigInt);
  Local<BigInt> result;
  has_exception =
      !ToLocal<BigInt>(i::BigInt::FromObject(i_isolate, obj), &result);
  RETURN_ON_FAILED_EXECUTION(BigInt);
  RETURN_ESCAPED(result);
}

bool Value::BooleanValue(Isolate* v8_isolate) const {
  return i::Object::BooleanValue(*Utils::OpenDirectHandle(this),
                                 reinterpret_cast<i::Isolate*>(v8_isolate));
}

MaybeLocal<Primitive> Value::ToPrimitive(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsPrimitive(*obj)) return ToApiHandle<Primitive>(obj);
  PREPARE_FOR_EXECUTION(context, Object, ToPrimitive);
  Local<Primitive> result;
  has_exception =
      !ToLocal<Primitive>(i::Object::ToPrimitive(i_isolate, obj), &result);
  RETURN_ON_FAILED_EXECUTION(Primitive);
  RETURN_ESCAPED(result);
}

MaybeLocal<Numeric> Value::ToNumeric(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsNumeric(*obj)) return ToApiHandle<Numeric>(obj);
  PREPARE_FOR_EXECUTION(context, Object, ToNumeric);
  Local<Numeric> result;
  has_exception =
      !ToLocal<Numeric>(i::Object::ToNumeric(i_isolate, obj), &result);
  RETURN_ON_FAILED_EXECUTION(Numeric);
  RETURN_ESCAPED(result);
}

Local<Boolean> Value::ToBoolean(Isolate* v8_isolate) const {
  auto i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return ToApiHandle<Boolean>(
      i_isolate->factory()->ToBoolean(BooleanValue(v8_isolate)));
}

MaybeLocal<Number> Value::ToNumber(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsNumber(*obj)) return ToApiHandle<Number>(obj);
  PREPARE_FOR_EXECUTION(context, Object, ToNumber);
  Local<Number> result;
  has_exception =
      !ToLocal<Number>(i::Object::ToNumber(i_isolate, obj), &result);
  RETURN_ON_FAILED_EXECUTION(Number);
  RETURN_ESCAPED(result);
}

MaybeLocal<Integer> Value::ToInteger(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsSmi(*obj)) return ToApiHandle<Integer>(obj);
  PREPARE_FOR_EXECUTION(context, Object, ToInteger);
  Local<Integer> result;
  has_exception =
      !ToLocal<Integer>(i::Object::ToInteger(i_isolate, obj), &result);
  RETURN_ON_FAILED_EXECUTION(Integer);
  RETURN_ESCAPED(result);
}

MaybeLocal<Int32> Value::ToInt32(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsSmi(*obj)) return ToApiHandle<Int32>(obj);
  Local<Int32> result;
  PREPARE_FOR_EXECUTION(context, Object, ToInt32);
  has_exception = !ToLocal<Int32>(i::Object::ToInt32(i_isolate, obj), &result);
  RETURN_ON_FAILED_EXECUTION(Int32);
  RETURN_ESCAPED(result);
}

MaybeLocal<Uint32> Value::ToUint32(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsSmi(*obj)) return ToApiHandle<Uint32>(obj);
  Local<Uint32> result;
  PREPARE_FOR_EXECUTION(context, Object, ToUint32);
  has_exception =
      !ToLocal<Uint32>(i::Object::ToUint32(i_isolate, obj), &result);
  RETURN_ON_FAILED_EXECUTION(Uint32);
  RETURN_ESCAPED(result);
}

i::Isolate* i::IsolateFromNeverReadOnlySpaceObject(i::Address obj) {
  return i::GetIsolateFromWritableObject(
      i::Cast<i::HeapObject>(i::Tagged<i::Object>(obj)));
}

namespace api_internal {
i::Address ConvertToJSGlobalProxyIfNecessary(i::Address holder_ptr) {
  i::Tagged<i::HeapObject> holder =
      i::Cast<i::HeapObject>(i::Tagged<i::Object>(holder_ptr));

  if (i::IsJSGlobalObject(holder)) {
    return i::Cast<i::JSGlobalObject>(holder)->global_proxy().ptr();
  }
  return holder_ptr;
}
}  // namespace api_internal

bool i::ShouldThrowOnError(i::Isolate* i_isolate) {
  return i::GetShouldThrow(i_isolate, Nothing<i::ShouldThrow>()) ==
         i::ShouldThrow::kThrowOnError;
}

void i::Internals::CheckInitializedImpl(v8::Isolate* external_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(external_isolate);
  Utils::ApiCheck(i_isolate != nullptr && !i_isolate->IsDead(),
                  "v8::internal::Internals::CheckInitialized",
                  "Isolate is not initialized or V8 has died");
}

void v8::Value::CheckCast(Data* that) {
  Utils::ApiCheck(that->IsValue(), "v8::Value::Cast", "Data is not a Value");
}

void External::CheckCast(v8::Value* that) {
  Utils::ApiCheck(that->IsExternal(), "v8::External::Cast",
                  "Value is not an External");
}

void v8::Object::CheckCast(Value* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsJSReceiver(*obj), "v8::Object::Cast",
                  "Value is not an Object");
}

void v8::Function::CheckCast(Value* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsCallable(*obj), "v8::Function::Cast",
                  "Value is not a Function");
}

void v8::Boolean::CheckCast(v8::Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsBoolean(*obj), "v8::Boolean::Cast",
                  "Value is not a Boolean");
}

void v8::Name::CheckCast(v8::Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsName(*obj), "v8::Name::Cast", "Value is not a Name");
}

void v8::String::CheckCast(v8::Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsString(*obj), "v8::String::Cast",
                  "Value is not a String");
}

void v8::Symbol::CheckCast(v8::Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsSymbol(*obj), "v8::Symbol::Cast",
                  "Value is not a Symbol");
}

void v8::Private::CheckCast(v8::Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(IsSymbol(*obj) && i::Cast<i::Symbol>(obj)->is_private(),
                  "v8::Private::Cast", "Value is not a Private");
}

void v8::FixedArray::CheckCast(v8::Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsFixedArray(*obj), "v8::FixedArray::Cast",
                  "Value is not a FixedArray");
}

void v8::ModuleRequest::CheckCast(v8::Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsModuleRequest(*obj), "v8::ModuleRequest::Cast",
                  "Value is not a ModuleRequest");
}

void v8::Module::CheckCast(v8::Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsModule(*obj), "v8::Module::Cast",
                  "Value is not a Module");
}

void v8::Numeric::CheckCast(v8::Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsNumeric(*obj), "v8::Numeric::Cast()",
                  "Value is not a Numeric");
}

void v8::Number::CheckCast(v8::Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsNumber(*obj), "v8::Number::Cast()",
                  "Value is not a Number");
}

void v8::Integer::CheckCast(v8::Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsNumber(*obj), "v8::Integer::Cast",
                  "Value is not an Integer");
}

void v8::Int32::CheckCast(v8::Data* that) {
  Utils::ApiCheck(Value::Cast(that)->IsInt32(), "v8::Int32::Cast",
                  "Value is not a 32-bit signed integer");
}

void v8::Uint32::CheckCast(v8::Data* that) {
  Utils::ApiCheck(Value::Cast(that)->IsUint32(), "v8::Uint32::Cast",
                  "Value is not a 32-bit unsigned integer");
}

void v8::BigInt::CheckCast(v8::Data* that) {
  Utils::ApiCheck(Value::Cast(that)->IsBigInt(), "v8::BigInt::Cast",
                  "Value is not a BigInt");
}

void v8::Context::CheckCast(v8::Data* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsContext(*obj), "v8::Context::Cast",
                  "Value is not a Context");
}

void v8::Array::CheckCast(Value* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsJSArray(*obj), "v8::Array::Cast",
                  "Value is not an Array");
}

void v8::Map::CheckCast(Value* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsJSMap(*obj), "v8::Map::Cast", "Value is not a Map");
}

void v8::Set::CheckCast(Value* that) {
  auto obj = Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsJSSet(*obj), "v8_Set_Cast", "Value is not a Set");
}

void v8::Promise::CheckCast(Value* that) {
  Utils::ApiCheck(that->IsPromise(), "v8
"""


```