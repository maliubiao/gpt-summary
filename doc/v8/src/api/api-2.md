Response: The user wants a summary of the provided C++ code snippet from `v8/src/api/api.cc`.
This is part 3 of 8, so it likely covers a specific set of functionalities.

Looking at the code, I see sections related to:
- `Message`: Getting source information of a message.
- `StackTrace` and `StackFrame`:  Retrieving and manipulating stack trace information.
- `JSON`: Parsing and stringifying JSON.
- `Value Serialization`: Serializing and deserializing JavaScript values.
- `Value Type Checking`:  A large number of `Is...` methods to determine the type of a `Value`.
- `Value Conversion`: Methods like `ToString`, `ToNumber`, `ToObject`, etc., to convert `Value` to other types.
- `Object Property Access and Modification`:  Methods like `Get`, `Set`, `DefineOwnProperty`, `GetPropertyNames`, `GetPrototype`, etc.

Based on this, the functionality seems to revolve around introspection and manipulation of JavaScript values and call stacks from the C++ API.

I need to summarize these functionalities and provide JavaScript examples where applicable.
这是 `v8/src/api/api.cc` 文件的一部分，主要负责提供 V8 引擎的 C++ API，用于获取和操作 JavaScript 运行时环境中的信息，特别是关于错误消息、调用栈、JSON 处理以及值的序列化和反序列化。

**主要功能归纳：**

1. **错误消息（Message）相关操作：**
   - `GetSource()`: 获取导致错误的源代码片段。
   - `GetSourceLine()`: 获取错误发生的源代码行。
   - `PrintCurrentStackTrace()`: 打印当前的调用栈信息到指定的输出流。

2. **调用栈（StackTrace 和 StackFrame）相关操作：**
   - `StackTrace::GetID()`: 获取调用栈的 ID。
   - `StackTrace::GetFrame()`: 获取调用栈中的指定帧（`StackFrame`）。
   - `StackTrace::GetFrameCount()`: 获取调用栈的帧数。
   - `StackTrace::CurrentStackTrace()`: 获取当前的调用栈信息。
   - `StackTrace::CurrentScriptNameOrSourceURL()`: 获取当前脚本的名称或来源 URL。
   - `StackFrame::GetLocation()`: 获取当前栈帧在脚本中的位置（行号和列号）。
   - `StackFrame::GetScriptId()`: 获取当前栈帧所属脚本的 ID。
   - `StackFrame::GetScriptName()`: 获取当前栈帧所属脚本的名称。
   - `StackFrame::GetScriptNameOrSourceURL()`: 获取当前栈帧所属脚本的名称或来源 URL。
   - `StackFrame::GetScriptSource()`: 获取当前栈帧所属脚本的源代码。
   - `StackFrame::GetScriptSourceMappingURL()`: 获取当前栈帧所属脚本的 Source Mapping URL。
   - `StackFrame::GetFunctionName()`: 获取当前栈帧对应的函数名。
   - `StackFrame::IsEval()`: 判断当前栈帧是否在 `eval()` 调用中。
   - `StackFrame::IsConstructor()`: 判断当前栈帧是否为构造函数调用。
   - `StackFrame::IsWasm()`: 判断当前栈帧是否在 WebAssembly 模块中。
   - `StackFrame::IsUserJavaScript()`: 判断当前栈帧是否在用户 JavaScript 代码中。

3. **JSON 处理（JSON）相关操作：**
   - `JSON::Parse()`: 将 JSON 字符串解析为 JavaScript 值。
   - `JSON::Stringify()`: 将 JavaScript 值转换为 JSON 字符串。

4. **值的序列化和反序列化（Value Serialization）相关操作：**
   - `ValueSerializer`: 用于将 JavaScript 值序列化为字节流。
     - `WriteHeader()`: 写入序列化头信息。
     - `WriteValue()`: 写入一个 JavaScript 值。
     - `Release()`: 释放序列化后的字节流。
     - `TransferArrayBuffer()`: 传输 ArrayBuffer。
     - `WriteUint32()`, `WriteUint64()`, `WriteDouble()`, `WriteRawBytes()`: 写入特定类型的数据。
   - `ValueDeserializer`: 用于将字节流反序列化为 JavaScript 值。
     - `ReadHeader()`: 读取序列化头信息。
     - `ReadValue()`: 读取一个 JavaScript 值。
     - `TransferArrayBuffer()`, `TransferSharedArrayBuffer()`: 传输 ArrayBuffer 或 SharedArrayBuffer。
     - `ReadUint32()`, `ReadUint64()`, `ReadDouble()`, `ReadRawBytes()`: 读取特定类型的数据。

5. **值的类型判断（Value 的 `Is...` 方法）：**
   - 提供了大量 `Is...` 方法，用于判断 `Value` 的具体类型，例如 `IsUndefined()`, `IsNull()`, `IsString()`, `IsArray()`, `IsObject()`, `IsFunction()`, `IsNumber()`, `IsBigInt()`, `IsPromise()` 等。

6. **值的类型转换（Value 的 `To...` 方法）：**
   - 提供了 `To...` 方法，用于将 `Value` 转换为其他类型，例如 `ToString()`, `ToNumber()`, `ToObject()`, `ToBoolean()`, `ToArrayIndex()` 等。

7. **对象属性访问和修改（Object 的方法）：**
   - `Set()`: 设置对象的属性值。
   - `CreateDataProperty()`: 创建一个新的数据属性。
   - `DefineOwnProperty()`: 定义或修改对象的自有属性的特性。
   - `SetPrivate()`: 设置对象的私有属性。
   - `Get()`: 获取对象的属性值。
   - `GetPrivate()`: 获取对象的私有属性值。
   - `GetPropertyAttributes()`: 获取对象属性的特性。
   - `GetOwnPropertyDescriptor()`: 获取对象自有属性的描述符。
   - `GetPrototype()` / `GetPrototypeV2()`: 获取对象的原型。
   - `SetPrototype()` / `SetPrototypeV2()`: 设置对象的原型。
   - `FindInstanceInPrototypeChain()`: 在原型链中查找特定构造函数的实例。
   - `GetPropertyNames()` / `GetOwnPropertyNames()`: 获取对象的可枚举或所有自有属性名。
   - `ObjectProtoToString()`: 调用 `Object.prototype.toString` 方法。

**与 JavaScript 功能的关系及示例：**

这些 C++ API 的功能直接对应了 JavaScript 中可观察和操作的行为。通过这些 API，V8 提供了在 C++ 代码中与 JavaScript 运行时进行交互的能力，例如：

- **错误处理和调试：**
  ```javascript
  try {
    throw new Error("Something went wrong!");
  } catch (e) {
    console.error(e.message); // 对应 Message::GetSource() 等
    console.error(e.stack);   // 对应 StackTrace 和 StackFrame 的相关操作
  }
  ```

- **JSON 操作：**
  ```javascript
  const jsonString = '{"name": "John", "age": 30}';
  const jsonObject = JSON.parse(jsonString); // 对应 JSON::Parse()
  console.log(jsonObject.name);

  const obj = { greeting: "Hello", target: "World" };
  const json = JSON.stringify(obj);        // 对应 JSON::Stringify()
  console.log(json);
  ```

- **值的类型判断和转换：**
  ```javascript
  const value = 123;
  console.log(typeof value === 'number'); // 对应 Value::IsNumber()
  console.log(value.toString());         // 对应 Value::ToString()

  const arr = [1, 2, 3];
  console.log(Array.isArray(arr));       // 对应 Value::IsArray()
  ```

- **对象属性操作：**
  ```javascript
  const obj = { a: 1 };
  obj.b = 2;                             // 对应 Object::Set()
  console.log(obj.a);                     // 对应 Object::Get()
  console.log(Object.keys(obj));          // 对应 Object::GetPropertyNames()

  const proto = { c: 3 };
  Object.setPrototypeOf(obj, proto);      // 对应 Object::SetPrototype()
  console.log(obj.c);
  ```

- **值的序列化（虽然 JavaScript 本身没有直接提供通用的序列化 API，但可以通过 V8 的 C++ API 实现类似的功能）：**
  V8 的 `ValueSerializer` 和 `ValueDeserializer` 可以用来实现跨进程或跨上下文的值传递和恢复，这在某些特定的 V8 宿主环境中非常有用。虽然 JavaScript 没有直接对应的 API，但一些库或框架可能会利用这些底层能力。

总而言之，这部分 C++ 代码是 V8 引擎提供给外部 C++ 环境操作 JavaScript 运行时状态和数据的桥梁，使得 C++ 代码能够更深入地集成和控制 V8 引擎。

Prompt: 
```
这是目录为v8/src/api/api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共8部分，请归纳一下它的功能

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
  Utils::ApiCheck(that->IsPromise(), "v8::Promise::Cast",
                  "Value is not a Promise");
}

void v8::Promise::Resolver::CheckCast(Value* that) {
  Utils::ApiCheck(that->IsPromise(), "v8::Promise::Resolver::Cast",
                  "Value is not a Promise::Resolver");
}

void v8::Proxy::CheckCast(Value* that) {
  Utils::ApiCheck(that->IsProxy(), "v8::Proxy::Cast", "Value is not a Proxy");
}

void v8::WasmMemoryObject::CheckCast(Value* that) {
  Utils::ApiCheck(that->IsWasmMemoryObject(), "v8::WasmMemoryObject::Cast",
                  "Value is not a WasmMemoryObject");
}

void v8::WasmModuleObject::CheckCast(Value* that) {
  Utils::ApiCheck(that->IsWasmModuleObject(), "v8::WasmModuleObject::Cast",
                  "Value is not a WasmModuleObject");
}

v8::BackingStore::~BackingStore() {
  auto i_this = reinterpret_cast<const i::BackingStore*>(this);
  i_this->~BackingStore();  // manually call internal destructor
}

void* v8::BackingStore::Data() const {
  return reinterpret_cast<const i::BackingStore*>(this)->buffer_start();
}

size_t v8::BackingStore::ByteLength() const {
  return reinterpret_cast<const i::BackingStore*>(this)->byte_length();
}

size_t v8::BackingStore::MaxByteLength() const {
  return reinterpret_cast<const i::BackingStore*>(this)->max_byte_length();
}

bool v8::BackingStore::IsShared() const {
  return reinterpret_cast<const i::BackingStore*>(this)->is_shared();
}

bool v8::BackingStore::IsResizableByUserJavaScript() const {
  return reinterpret_cast<const i::BackingStore*>(this)->is_resizable_by_js();
}

// static
std::unique_ptr<v8::BackingStore> v8::BackingStore::Reallocate(
    v8::Isolate* v8_isolate, std::unique_ptr<v8::BackingStore> backing_store,
    size_t byte_length) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, ArrayBuffer, BackingStore_Reallocate);
  Utils::ApiCheck(byte_length <= i::JSArrayBuffer::kMaxByteLength,
                  "v8::BackingStore::Reallocate", "byte_length is too large");
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::BackingStore* i_backing_store =
      reinterpret_cast<i::BackingStore*>(backing_store.get());
  if (!i_backing_store->Reallocate(i_isolate, byte_length)) {
    i::V8::FatalProcessOutOfMemory(i_isolate, "v8::BackingStore::Reallocate");
  }
  return backing_store;
}

// static
void v8::BackingStore::EmptyDeleter(void* data, size_t length,
                                    void* deleter_data) {
  DCHECK_NULL(deleter_data);
}

std::shared_ptr<v8::BackingStore> v8::ArrayBuffer::GetBackingStore() {
  auto self = Utils::OpenDirectHandle(this);
  std::shared_ptr<i::BackingStore> backing_store = self->GetBackingStore();
  if (!backing_store) {
    backing_store =
        i::BackingStore::EmptyBackingStore(i::SharedFlag::kNotShared);
  }
  std::shared_ptr<i::BackingStoreBase> bs_base = backing_store;
  return std::static_pointer_cast<v8::BackingStore>(bs_base);
}

void* v8::ArrayBuffer::Data() const {
  return Utils::OpenDirectHandle(this)->backing_store();
}

bool v8::ArrayBuffer::IsResizableByUserJavaScript() const {
  return Utils::OpenDirectHandle(this)->is_resizable_by_js();
}

std::shared_ptr<v8::BackingStore> v8::SharedArrayBuffer::GetBackingStore() {
  auto self = Utils::OpenDirectHandle(this);
  std::shared_ptr<i::BackingStore> backing_store = self->GetBackingStore();
  if (!backing_store) {
    backing_store = i::BackingStore::EmptyBackingStore(i::SharedFlag::kShared);
  }
  std::shared_ptr<i::BackingStoreBase> bs_base = backing_store;
  return std::static_pointer_cast<v8::BackingStore>(bs_base);
}

void* v8::SharedArrayBuffer::Data() const {
  return Utils::OpenDirectHandle(this)->backing_store();
}

void v8::ArrayBuffer::CheckCast(Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(
      IsJSArrayBuffer(obj) && !i::Cast<i::JSArrayBuffer>(obj)->is_shared(),
      "v8::ArrayBuffer::Cast()", "Value is not an ArrayBuffer");
}

void v8::ArrayBufferView::CheckCast(Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsJSArrayBufferView(obj), "v8::ArrayBufferView::Cast()",
                  "Value is not an ArrayBufferView");
}

void v8::TypedArray::CheckCast(Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsJSTypedArray(obj), "v8::TypedArray::Cast()",
                  "Value is not a TypedArray");
}

#define CHECK_TYPED_ARRAY_CAST(Type, typeName, TYPE, ctype)                \
  void v8::Type##Array::CheckCast(Value* that) {                           \
    auto obj = *Utils::OpenDirectHandle(that);                             \
    Utils::ApiCheck(                                                       \
        i::IsJSTypedArray(obj) && i::Cast<i::JSTypedArray>(obj)->type() == \
                                      i::kExternal##Type##Array,           \
        "v8::" #Type "Array::Cast()", "Value is not a " #Type "Array");    \
  }

TYPED_ARRAYS_BASE(CHECK_TYPED_ARRAY_CAST)
#undef CHECK_TYPED_ARRAY_CAST

void v8::Float16Array::CheckCast(Value* that) {
  Utils::ApiCheck(i::v8_flags.js_float16array, "v8::Float16Array::Cast",
                  "Float16Array is not supported");
  auto obj = *Utils::OpenHandle(that);
  Utils::ApiCheck(
      i::IsJSTypedArray(obj) &&
          i::Cast<i::JSTypedArray>(obj)->type() == i::kExternalFloat16Array,
      "v8::Float16Array::Cast()", "Value is not a Float16Array");
}

void v8::DataView::CheckCast(Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsJSDataView(obj) || IsJSRabGsabDataView(obj),
                  "v8::DataView::Cast()", "Value is not a DataView");
}

void v8::SharedArrayBuffer::CheckCast(Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(
      IsJSArrayBuffer(obj) && i::Cast<i::JSArrayBuffer>(obj)->is_shared(),
      "v8::SharedArrayBuffer::Cast()", "Value is not a SharedArrayBuffer");
}

void v8::Date::CheckCast(v8::Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsJSDate(obj), "v8::Date::Cast()", "Value is not a Date");
}

void v8::StringObject::CheckCast(v8::Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsStringWrapper(obj), "v8::StringObject::Cast()",
                  "Value is not a StringObject");
}

void v8::SymbolObject::CheckCast(v8::Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsSymbolWrapper(obj), "v8::SymbolObject::Cast()",
                  "Value is not a SymbolObject");
}

void v8::NumberObject::CheckCast(v8::Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsNumberWrapper(obj), "v8::NumberObject::Cast()",
                  "Value is not a NumberObject");
}

void v8::BigIntObject::CheckCast(v8::Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsBigIntWrapper(obj), "v8::BigIntObject::Cast()",
                  "Value is not a BigIntObject");
}

void v8::BooleanObject::CheckCast(v8::Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsBooleanWrapper(obj), "v8::BooleanObject::Cast()",
                  "Value is not a BooleanObject");
}

void v8::RegExp::CheckCast(v8::Value* that) {
  auto obj = *Utils::OpenDirectHandle(that);
  Utils::ApiCheck(i::IsJSRegExp(obj), "v8::RegExp::Cast()",
                  "Value is not a RegExp");
}

Maybe<double> Value::NumberValue(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsNumber(*obj)) {
    return Just(i::Object::NumberValue(i::Cast<i::Number>(*obj)));
  }
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Value, NumberValue, i::HandleScope);
  i::Handle<i::Number> num;
  has_exception = !i::Object::ToNumber(i_isolate, obj).ToHandle(&num);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(double);
  return Just(i::Object::NumberValue(*num));
}

Maybe<int64_t> Value::IntegerValue(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsNumber(*obj)) {
    return Just(NumberToInt64(*obj));
  }
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Value, IntegerValue, i::HandleScope);
  i::Handle<i::Object> num;
  has_exception = !i::Object::ToInteger(i_isolate, obj).ToHandle(&num);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(int64_t);
  return Just(NumberToInt64(*num));
}

Maybe<int32_t> Value::Int32Value(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsNumber(*obj)) return Just(NumberToInt32(*obj));
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Value, Int32Value, i::HandleScope);
  i::Handle<i::Object> num;
  has_exception = !i::Object::ToInt32(i_isolate, obj).ToHandle(&num);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(int32_t);
  return Just(IsSmi(*num) ? i::Smi::ToInt(*num)
                          : static_cast<int32_t>(
                                i::Cast<i::HeapNumber>(*num)->value()));
}

Maybe<uint32_t> Value::Uint32Value(Local<Context> context) const {
  auto obj = Utils::OpenHandle(this);
  if (i::IsNumber(*obj)) return Just(NumberToUint32(*obj));
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Value, Uint32Value, i::HandleScope);
  i::Handle<i::Object> num;
  has_exception = !i::Object::ToUint32(i_isolate, obj).ToHandle(&num);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(uint32_t);
  return Just(IsSmi(*num) ? static_cast<uint32_t>(i::Smi::ToInt(*num))
                          : static_cast<uint32_t>(
                                i::Cast<i::HeapNumber>(*num)->value()));
}

MaybeLocal<Uint32> Value::ToArrayIndex(Local<Context> context) const {
  auto self = Utils::OpenHandle(this);
  if (i::IsSmi(*self)) {
    if (i::Smi::ToInt(*self) >= 0) return Utils::Uint32ToLocal(self);
    return Local<Uint32>();
  }
  PREPARE_FOR_EXECUTION(context, Object, ToArrayIndex);
  i::Handle<i::Object> string_obj;
  has_exception = !i::Object::ToString(i_isolate, self).ToHandle(&string_obj);
  RETURN_ON_FAILED_EXECUTION(Uint32);
  auto str = i::Cast<i::String>(string_obj);
  uint32_t index;
  if (str->AsArrayIndex(&index)) {
    i::Handle<i::Object> value;
    if (index <= static_cast<uint32_t>(i::Smi::kMaxValue)) {
      value = i::Handle<i::Object>(i::Smi::FromInt(index), i_isolate);
    } else {
      value = i_isolate->factory()->NewNumber(index);
    }
    RETURN_ESCAPED(Utils::Uint32ToLocal(value));
  }
  return Local<Uint32>();
}

Maybe<bool> Value::Equals(Local<Context> context, Local<Value> that) const {
  i::Isolate* i_isolate = Utils::OpenDirectHandle(*context)->GetIsolate();
  ENTER_V8(i_isolate, context, Value, Equals, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto other = Utils::OpenHandle(*that);
  Maybe<bool> result = i::Object::Equals(i_isolate, self, other);
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return result;
}

bool Value::StrictEquals(Local<Value> that) const {
  auto self = Utils::OpenHandle(this);
  auto other = Utils::OpenHandle(*that);
  return i::Object::StrictEquals(*self, *other);
}

bool Value::SameValue(Local<Value> that) const {
  auto self = Utils::OpenHandle(this);
  auto other = Utils::OpenHandle(*that);
  return i::Object::SameValue(*self, *other);
}

Local<String> Value::TypeOf(v8::Isolate* external_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(external_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  API_RCS_SCOPE(i_isolate, Value, TypeOf);
  return Utils::ToLocal(i::Object::TypeOf(i_isolate, Utils::OpenHandle(this)));
}

Maybe<bool> Value::InstanceOf(v8::Local<v8::Context> context,
                              v8::Local<v8::Object> object) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Value, InstanceOf, i::HandleScope);
  i::Handle<i::JSAny> left;
  if (!Utils::ApiCheck(i::TryCast<i::JSAny>(Utils::OpenHandle(this), &left),
                       "Value::InstanceOf",
                       "Invalid type, must be a JS primitive or object.")) {
    return Nothing<bool>();
  }
  auto right = Utils::OpenHandle(*object);
  i::Handle<i::Object> result;
  has_exception =
      !i::Object::InstanceOf(i_isolate, left, right).ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(i::IsTrue(*result, i_isolate));
}

Maybe<bool> v8::Object::Set(v8::Local<v8::Context> context,
                            v8::Local<Value> key, v8::Local<Value> value) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, Set, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  auto value_obj = Utils::OpenHandle(*value);
  has_exception =
      i::Runtime::SetObjectProperty(i_isolate, self, key_obj, value_obj,
                                    i::StoreOrigin::kMaybeKeyed,
                                    Just(i::ShouldThrow::kDontThrow))
          .is_null();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(true);
}

Maybe<bool> v8::Object::Set(v8::Local<v8::Context> context,
                            v8::Local<Value> key, v8::Local<Value> value,
                            MaybeLocal<Object> receiver) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, Set, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  auto value_obj = Utils::OpenHandle(*value);
  i::MaybeHandle<i::JSReceiver> receiver_obj;
  if (!receiver.IsEmpty()) {
    receiver_obj = Utils::OpenHandle(*receiver.ToLocalChecked());
  }
  has_exception =
      i::Runtime::SetObjectProperty(i_isolate, self, key_obj, value_obj,
                                    receiver_obj, i::StoreOrigin::kMaybeKeyed,
                                    Just(i::ShouldThrow::kDontThrow))
          .is_null();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(true);
}

Maybe<bool> v8::Object::Set(v8::Local<v8::Context> context, uint32_t index,
                            v8::Local<Value> value) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, Set, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto value_obj = Utils::OpenHandle(*value);
  has_exception = i::Object::SetElement(i_isolate, self, index, value_obj,
                                        i::ShouldThrow::kDontThrow)
                      .is_null();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(true);
}

Maybe<bool> v8::Object::CreateDataProperty(v8::Local<v8::Context> context,
                                           v8::Local<Name> key,
                                           v8::Local<Value> value) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  auto value_obj = Utils::OpenHandle(*value);

  i::PropertyKey lookup_key(i_isolate, key_obj);
  if (i::IsJSObject(*self)) {
    ENTER_V8_NO_SCRIPT(i_isolate, context, Object, CreateDataProperty,
                       i::HandleScope);
    Maybe<bool> result = i::JSObject::CreateDataProperty(
        i_isolate, i::Cast<i::JSObject>(self), lookup_key, value_obj,
        Just(i::kDontThrow));
    has_exception = result.IsNothing();
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
    return result;
  }
  // JSProxy or WasmObject or other non-JSObject.
  ENTER_V8(i_isolate, context, Object, CreateDataProperty, i::HandleScope);
  Maybe<bool> result = i::JSReceiver::CreateDataProperty(
      i_isolate, self, lookup_key, value_obj, Just(i::kDontThrow));
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return result;
}

Maybe<bool> v8::Object::CreateDataProperty(v8::Local<v8::Context> context,
                                           uint32_t index,
                                           v8::Local<Value> value) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  auto self = Utils::OpenHandle(this);
  auto value_obj = Utils::OpenHandle(*value);

  i::PropertyKey lookup_key(i_isolate, index);
  if (i::IsJSObject(*self)) {
    ENTER_V8_NO_SCRIPT(i_isolate, context, Object, CreateDataProperty,
                       i::HandleScope);
    Maybe<bool> result = i::JSObject::CreateDataProperty(
        i_isolate, i::Cast<i::JSObject>(self), lookup_key, value_obj,
        Just(i::kDontThrow));
    has_exception = result.IsNothing();
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
    return result;
  }
  // JSProxy or WasmObject or other non-JSObject.
  ENTER_V8(i_isolate, context, Object, CreateDataProperty, i::HandleScope);
  Maybe<bool> result = i::JSReceiver::CreateDataProperty(
      i_isolate, self, lookup_key, value_obj, Just(i::kDontThrow));
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return result;
}

struct v8::PropertyDescriptor::PrivateData {
  PrivateData() : desc() {}
  i::PropertyDescriptor desc;
};

v8::PropertyDescriptor::PropertyDescriptor() : private_(new PrivateData()) {}

// DataDescriptor
v8::PropertyDescriptor::PropertyDescriptor(v8::Local<v8::Value> value)
    : private_(new PrivateData()) {
  private_->desc.set_value(Cast<i::JSAny>(Utils::OpenHandle(*value, true)));
}

// DataDescriptor with writable field
v8::PropertyDescriptor::PropertyDescriptor(v8::Local<v8::Value> value,
                                           bool writable)
    : private_(new PrivateData()) {
  private_->desc.set_value(Cast<i::JSAny>(Utils::OpenHandle(*value, true)));
  private_->desc.set_writable(writable);
}

// AccessorDescriptor
v8::PropertyDescriptor::PropertyDescriptor(v8::Local<v8::Value> get,
                                           v8::Local<v8::Value> set)
    : private_(new PrivateData()) {
  DCHECK(get.IsEmpty() || get->IsUndefined() || get->IsFunction());
  DCHECK(set.IsEmpty() || set->IsUndefined() || set->IsFunction());
  private_->desc.set_get(Cast<i::JSAny>(Utils::OpenHandle(*get, true)));
  private_->desc.set_set(Cast<i::JSAny>(Utils::OpenHandle(*set, true)));
}

v8::PropertyDescriptor::~PropertyDescriptor() { delete private_; }

v8::Local<Value> v8::PropertyDescriptor::value() const {
  DCHECK(private_->desc.has_value());
  return Utils::ToLocal(private_->desc.value());
}

v8::Local<Value> v8::PropertyDescriptor::get() const {
  DCHECK(private_->desc.has_get());
  return Utils::ToLocal(private_->desc.get());
}

v8::Local<Value> v8::PropertyDescriptor::set() const {
  DCHECK(private_->desc.has_set());
  return Utils::ToLocal(private_->desc.set());
}

bool v8::PropertyDescriptor::has_value() const {
  return private_->desc.has_value();
}
bool v8::PropertyDescriptor::has_get() const {
  return private_->desc.has_get();
}
bool v8::PropertyDescriptor::has_set() const {
  return private_->desc.has_set();
}

bool v8::PropertyDescriptor::writable() const {
  DCHECK(private_->desc.has_writable());
  return private_->desc.writable();
}

bool v8::PropertyDescriptor::has_writable() const {
  return private_->desc.has_writable();
}

void v8::PropertyDescriptor::set_enumerable(bool enumerable) {
  private_->desc.set_enumerable(enumerable);
}

bool v8::PropertyDescriptor::enumerable() const {
  DCHECK(private_->desc.has_enumerable());
  return private_->desc.enumerable();
}

bool v8::PropertyDescriptor::has_enumerable() const {
  return private_->desc.has_enumerable();
}

void v8::PropertyDescriptor::set_configurable(bool configurable) {
  private_->desc.set_configurable(configurable);
}

bool v8::PropertyDescriptor::configurable() const {
  DCHECK(private_->desc.has_configurable());
  return private_->desc.configurable();
}

bool v8::PropertyDescriptor::has_configurable() const {
  return private_->desc.has_configurable();
}

Maybe<bool> v8::Object::DefineOwnProperty(v8::Local<v8::Context> context,
                                          v8::Local<Name> key,
                                          v8::Local<Value> value,
                                          v8::PropertyAttribute attributes) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  auto value_obj = Utils::OpenHandle(*value);

  i::PropertyDescriptor desc;
  desc.set_writable(!(attributes & v8::ReadOnly));
  desc.set_enumerable(!(attributes & v8::DontEnum));
  desc.set_configurable(!(attributes & v8::DontDelete));
  desc.set_value(i::Cast<i::JSAny>(value_obj));

  if (i::IsJSObject(*self)) {
    // If it's not a JSProxy, i::JSReceiver::DefineOwnProperty should never run
    // a script.
    ENTER_V8_NO_SCRIPT(i_isolate, context, Object, DefineOwnProperty,
                       i::HandleScope);
    Maybe<bool> success = i::JSReceiver::DefineOwnProperty(
        i_isolate, self, key_obj, &desc, Just(i::kDontThrow));
    has_exception = success.IsNothing();
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
    return success;
  }
  // JSProxy or WasmObject or other non-JSObject.
  ENTER_V8(i_isolate, context, Object, DefineOwnProperty, i::HandleScope);
  Maybe<bool> success = i::JSReceiver::DefineOwnProperty(
      i_isolate, self, key_obj, &desc, Just(i::kDontThrow));
  // Even though we said kDontThrow, there might be accessors that do throw.
  has_exception = success.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return success;
}

Maybe<bool> v8::Object::DefineProperty(v8::Local<v8::Context> context,
                                       v8::Local<Name> key,
                                       PropertyDescriptor& descriptor) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, DefineOwnProperty, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);

  Maybe<bool> success = i::JSReceiver::DefineOwnProperty(
      i_isolate, self, key_obj, &descriptor.get_private()->desc,
      Just(i::kDontThrow));
  has_exception = success.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return success;
}

Maybe<bool> v8::Object::SetPrivate(Local<Context> context, Local<Private> key,
                                   Local<Value> value) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8_NO_SCRIPT(i_isolate, context, Object, SetPrivate, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(reinterpret_cast<Name*>(*key));
  auto value_obj = Utils::OpenHandle(*value);
  if (i::IsJSObject(*self)) {
    auto js_object = i::Cast<i::JSObject>(self);
    i::LookupIterator it(i_isolate, js_object, key_obj, js_object);
    has_exception = i::JSObject::DefineOwnPropertyIgnoreAttributes(
                        &it, value_obj, i::DONT_ENUM)
                        .is_null();
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
    return Just(true);
  }
  if (i::IsJSProxy(*self)) {
    i::PropertyDescriptor desc;
    desc.set_writable(true);
    desc.set_enumerable(false);
    desc.set_configurable(true);
    desc.set_value(i::Cast<i::JSAny>(value_obj));
    return i::JSProxy::SetPrivateSymbol(i_isolate, i::Cast<i::JSProxy>(self),
                                        i::Cast<i::Symbol>(key_obj), &desc,
                                        Just(i::kDontThrow));
  }
  // Wasm object, or other kind of special object not supported here.
  return Just(false);
}

MaybeLocal<Value> v8::Object::Get(Local<v8::Context> context,
                                  Local<Value> key) {
  PREPARE_FOR_EXECUTION(context, Object, Get);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  i::Handle<i::Object> result;
  has_exception = !i::Runtime::GetObjectProperty(i_isolate, self, key_obj)
                       .ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(Utils::ToLocal(result));
}

MaybeLocal<Value> v8::Object::Get(Local<v8::Context> context, Local<Value> key,
                                  MaybeLocal<Object> receiver) {
  PREPARE_FOR_EXECUTION(context, Object, Get);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  i::Handle<i::JSReceiver> receiver_obj;
  if (!receiver.IsEmpty()) {
    receiver_obj = Utils::OpenHandle(*receiver.ToLocalChecked());
  }
  i::Handle<i::Object> result;
  has_exception =
      !i::Runtime::GetObjectProperty(i_isolate, self, key_obj, receiver_obj)
           .ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(Utils::ToLocal(result));
}

MaybeLocal<Value> v8::Object::Get(Local<Context> context, uint32_t index) {
  PREPARE_FOR_EXECUTION(context, Object, Get);
  auto self = Utils::OpenHandle(this);
  i::Handle<i::Object> result;
  has_exception =
      !i::JSReceiver::GetElement(i_isolate, self, index).ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(Utils::ToLocal(result));
}

MaybeLocal<Value> v8::Object::GetPrivate(Local<Context> context,
                                         Local<Private> key) {
  return Get(context, key.UnsafeAs<Value>());
}

Maybe<PropertyAttribute> v8::Object::GetPropertyAttributes(
    Local<Context> context, Local<Value> key) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Object, GetPropertyAttributes, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto key_obj = Utils::OpenHandle(*key);
  if (!i::IsName(*key_obj)) {
    has_exception = !i::Object::ToString(i_isolate, key_obj).ToHandle(&key_obj);
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(PropertyAttribute);
  }
  auto key_name = i::Cast<i::Name>(key_obj);
  auto result = i::JSReceiver::GetPropertyAttributes(self, key_name);
  has_exception = result.IsNothing();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(PropertyAttribute);
  if (result.FromJust() == i::ABSENT) {
    return Just(static_cast<PropertyAttribute>(i::NONE));
  }
  return Just(static_cast<PropertyAttribute>(result.FromJust()));
}

MaybeLocal<Value> v8::Object::GetOwnPropertyDescriptor(Local<Context> context,
                                                       Local<Name> key) {
  PREPARE_FOR_EXECUTION(context, Object, GetOwnPropertyDescriptor);
  auto obj = Utils::OpenHandle(this);
  auto key_name = Utils::OpenHandle(*key);

  i::PropertyDescriptor desc;
  Maybe<bool> found =
      i::JSReceiver::GetOwnPropertyDescriptor(i_isolate, obj, key_name, &desc);
  has_exception = found.IsNothing();
  RETURN_ON_FAILED_EXECUTION(Value);
  if (!found.FromJust()) {
    return v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate));
  }
  RETURN_ESCAPED(Utils::ToLocal(desc.ToObject(i_isolate)));
}

Local<Value> v8::Object::GetPrototype() {
  auto self = Utils::OpenHandle(this);
  auto i_isolate = self->GetIsolate();
  i::PrototypeIterator iter(i_isolate, self);
  return Utils::ToLocal(i::PrototypeIterator::GetCurrent(iter));
}

Local<Value> v8::Object::GetPrototypeV2() {
  auto self = Utils::OpenHandle(this);
  auto i_isolate = self->GetIsolate();
  i::PrototypeIterator iter(i_isolate, self);
  if (i::IsJSGlobalProxy(*self)) {
    // Skip hidden prototype (i.e. JSGlobalObject).
    iter.Advance();
  }
  DCHECK(!i::IsJSGlobalObject(*i::PrototypeIterator::GetCurrent(iter)));
  return Utils::ToLocal(i::PrototypeIterator::GetCurrent(iter));
}

namespace {

Maybe<bool> SetPrototypeImpl(v8::Object* this_, Local<Context> context,
                             Local<Value> value, bool from_javascript) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  auto self = Utils::OpenHandle(this_);
  auto value_obj = Utils::OpenHandle(*value);
  // TODO(333672197): turn this to DCHECK once it's no longer possible
  // to get JSGlobalObject via API.
  CHECK_IMPLIES(from_javascript, !i::IsJSGlobalObject(*value_obj));
  if (i::IsJSObject(*self)) {
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    // TODO(333672197): turn this to DCHECK once it's no longer possible
    // to get JSGlobalObject via API.
    CHECK_IMPLIES(from_javascript, !i::IsJSGlobalObject(*self));
    auto result =
        i::JSObject::SetPrototype(i_isolate, i::Cast<i::JSObject>(self),
                                  value_obj, from_javascript, i::kDontThrow);
    if (!result.FromJust()) return Nothing<bool>();
    return Just(true);
  }
  if (i::IsJSProxy(*self)) {
    ENTER_V8(i_isolate, context, Object, SetPrototype, i::HandleScope);
    // We do not allow exceptions thrown while setting the prototype
    // to propagate outside.
    TryCatch try_catch(reinterpret_cast<v8::Isolate*>(i_isolate));
    auto result =
        i::JSProxy::SetPrototype(i_isolate, i::Cast<i::JSProxy>(self),
                                 value_obj, from_javascript, i::kThrowOnError);
    has_exception = result.IsNothing();
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
    return Just(true);
  }
  // Wasm object or other kind of special object not supported here.
  return Nothing<bool>();
}

}  // namespace

Maybe<bool> v8::Object::SetPrototype(Local<Context> context,
                                     Local<Value> value) {
  static constexpr bool from_javascript = false;
  return SetPrototypeImpl(this, context, value, from_javascript);
}

Maybe<bool> v8::Object::SetPrototypeV2(Local<Context> context,
                                       Local<Value> value) {
  static constexpr bool from_javascript = true;
  return SetPrototypeImpl(this, context, value, from_javascript);
}

Local<Object> v8::Object::FindInstanceInPrototypeChain(
    v8::Local<FunctionTemplate> tmpl) {
  auto self = Utils::OpenDirectHandle(this);
  auto i_isolate = self->GetIsolate();
  i::PrototypeIterator iter(i_isolate, *self, i::kStartAtReceiver);
  i::Tagged<i::FunctionTemplateInfo> tmpl_info =
      *Utils::OpenDirectHandle(*tmpl);
  if (!IsJSObject(iter.GetCurrent())) return Local<Object>();
  while (!tmpl_info->IsTemplateFor(iter.GetCurrent<i::JSObject>())) {
    iter.Advance();
    if (iter.IsAtEnd()) return Local<Object>();
    if (!IsJSObject(iter.GetCurrent())) return Local<Object>();
  }
  // IsTemplateFor() ensures that iter.GetCurrent() can't be a Proxy here.
  return Utils::ToLocal(i::handle(iter.GetCurrent<i::JSObject>(), i_isolate));
}

MaybeLocal<Array> v8::Object::GetPropertyNames(Local<Context> context) {
  return GetPropertyNames(
      context, v8::KeyCollectionMode::kIncludePrototypes,
      static_cast<v8::PropertyFilter>(ONLY_ENUMERABLE | SKIP_SYMBOLS),
      v8::IndexFilter::kIncludeIndices);
}

MaybeLocal<Array> v8::Object::GetPropertyNames(
    Local<Context> context, KeyCollectionMode mode,
    PropertyFilter property_filter, IndexFilter index_filter,
    KeyConversionMode key_conversion) {
  PREPARE_FOR_EXECUTION(context, Object, GetPropertyNames);
  auto self = Utils::OpenHandle(this);
  i::DirectHandle<i::FixedArray> value;
  i::KeyAccumulator accumulator(
      i_isolate, static_cast<i::KeyCollectionMode>(mode),
      static_cast<i::PropertyFilter>(property_filter));
  accumulator.set_skip_indices(index_filter == IndexFilter::kSkipIndices);
  has_exception = accumulator.CollectKeys(self, self).IsNothing();
  RETURN_ON_FAILED_EXECUTION(Array);
  value =
      accumulator.GetKeys(static_cast<i::GetKeysConversion>(key_conversion));
  DCHECK(self->map()->EnumLength() == i::kInvalidEnumCacheSentinel ||
         self->map()->EnumLength() == 0 ||
         self->map()->instance_descriptors(i_isolate)->enum_cache()->keys() !=
             *value);
  auto result = i_isolate->factory()->NewJSArrayWithElements(value);
  RETURN_ESCAPED(Utils::ToLocal(result));
}

MaybeLocal<Array> v8::Object::GetOwnPropertyNames(Local<Context> context) {
  return GetOwnPropertyNames(
      context, static_cast<v8::PropertyFilter>(ONLY_ENUMERABLE | SKIP_SYMBOLS));
}

MaybeLocal<Array> v8::Object::GetOwnPropertyNames(
    Local<Context> context, PropertyFilter filter,
    KeyConversionMode key_conversion) {
  return GetPropertyNames(context, KeyCollectionMode::kOwnOnly, filter,
                          v8::IndexFilter::kIncludeIndices, key_conversion);
}

MaybeLocal<String> v8::Object::ObjectProtoToString(Local<Context> context) {
  PREPARE_FOR_EXECUTION(context, Object, ObjectProtoToString);
  auto self = Utils::OpenHandle(this);
  Local<Value> result;
  has_exception = !ToLocal<Value>(
      i::Execution::CallBuiltin(i_isolate, i_isolate->object_to_string(), self,
                                0, nullptr),
      &result);
  RETURN_ON_FAILED_EXECUTION(String);
  RETURN_ESCAPED(Local<String>::Cast(result));
}

Local<String> v8::Object:
"""


```