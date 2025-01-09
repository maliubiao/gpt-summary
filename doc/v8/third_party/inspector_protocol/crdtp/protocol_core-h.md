Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Identify the Core Purpose:** The filename `protocol_core.h` and the namespace `v8_crdtp` strongly suggest this file defines fundamental building blocks for a communication protocol. The `crdtp` likely stands for Chrome Remote Debugging Protocol, hinting at its role in debugging and interaction with V8.

2. **Scan for Major Components:**  Quickly read through the code, looking for class definitions and key data structures. Notice:
    * `DeserializerState`:  Seems related to receiving and interpreting data.
    * `ProtocolTypeTraits`: A template struct, probably for customizing serialization/deserialization behavior for different data types.
    * `ContainerSerializer`, `ObjectSerializer`:  Likely involved in packaging data for sending.
    * `DeserializerDescriptor`:  Appears to define how to extract data from a serialized format.
    * `DeferredMessage`:  A way to handle messages without immediate processing.
    * `DeserializableProtocolObject`, `ProtocolObject`: Base classes suggesting an object-oriented approach to protocol data.
    * Macros like `DECLARE_DESERIALIZATION_SUPPORT`, `DECLARE_SERIALIZATION_SUPPORT`, etc.:  Code generation or convenience features.

3. **Analyze Individual Components (Iterative and Focused):**

    * **`DeserializerState`:**
        * Focus on its responsibilities: managing the raw byte stream (`Storage`), tracking parsing progress (`CBORTokenizer`), and handling errors.
        * Pay attention to methods like `RegisterError`, `RegisterFieldPath`, and `ErrorMessage`. These point to error handling and debugging capabilities.

    * **`ProtocolTypeTraits`:**
        * Recognize the specialization for basic types (`bool`, `int32_t`, `double`). This is a common pattern for type-specific logic.
        * Understand the purpose of `Deserialize` and `Serialize` functions.

    * **Serializers (`ContainerSerializer`, `ObjectSerializer`):**
        * `ContainerSerializer`:  Seems to handle encoding fields within a structure (like a map or array). The `AddField` methods are key.
        * `ObjectSerializer`:  Might manage the overall serialization of an object, possibly using `ContainerSerializer` internally. The `Finish` method is important for completing the serialization.

    * **`DeserializerDescriptor`:**
        * The `Field` struct clearly defines how to map serialized data to object members.
        * The `Deserialize` method is the core logic for extracting data. The `seen_mandatory_fields` argument suggests handling optional fields.

    * **`DeferredMessage`:** The name suggests delayed processing. The `FromSerializable` and `FromSpan` methods indicate different ways to create these messages. `MakeDeserializer` is the crucial step to actually start interpreting the message.

    * **`DeserializableProtocolObject`, `ProtocolObject`:**
        * `DeserializableProtocolObject`: Provides static methods (`ReadFrom`, `FromBinary`, `Deserialize`) for creating objects from serialized data.
        * `ProtocolObject`: Inherits from `DeserializableProtocolObject` and adds serialization capabilities (`AppendSerialized`, `Clone`).

    * **Macros:** Understand their purpose – simplifying the declaration of serialization/deserialization logic within classes.

4. **Infer Relationships and Workflow:**

    * Serialization likely involves creating a `ProtocolObject`, populating its fields, and then calling `AppendSerialized`.
    * Deserialization involves receiving raw bytes, creating a `DeferredMessage` (or `DeserializerState` directly), and then using the `Deserialize` methods (potentially through `DeserializerDescriptor`) to populate a `DeserializableProtocolObject`. `ProtocolTypeTraits` provides the type-specific logic.

5. **Consider the Context (CRDP):** Remember that this code is likely part of the Chrome Remote Debugging Protocol. This means it's used for communication between a debugger (or developer tool) and a V8 runtime (like in Chrome or Node.js). This context helps understand the need for serialization and deserialization.

6. **Address Specific Questions from the Prompt:**

    * **Functionality:** Summarize the purpose of each major component based on the analysis above.
    * **`.tq` Extension:** Recognize that `.tq` signifies Torque and that this file is `.h`, therefore C++.
    * **Relationship to JavaScript:** Connect the serialization/deserialization to the need for representing JavaScript objects and data structures when communicating between different parts of V8 or with external tools. Think about how a JavaScript object's properties could be serialized and sent over the protocol.
    * **JavaScript Examples:** Devise simple JavaScript examples of data structures that would need to be serialized/deserialized (e.g., objects, arrays, primitive types).
    * **Code Logic Reasoning:**  Focus on the `DeserializerDescriptor::Deserialize` method. Imagine an input byte stream and how it would be parsed based on the defined `Field` list. Create a simple example with mandatory and optional fields.
    * **Common Programming Errors:** Think about typical issues in serialization/deserialization: type mismatches, missing mandatory fields, incorrect data formats.

7. **Structure the Answer:** Organize the findings logically, starting with a high-level overview and then going into details for each component. Use clear and concise language. Provide code examples and explanations where necessary.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the individual methods. It's important to step back and understand the overall flow of serialization and deserialization.
* If unsure about the purpose of a specific class or method, look for clues in its name, member variables, and how it's used by other parts of the code.
* The macros might seem complex at first, but recognize they are just code generation tools to reduce boilerplate. Focus on what they *do* rather than every detail of *how* they do it.
* The CRDP context is crucial. Always keep in mind the intended use case of this code.

By following these steps, and iterating through the code while keeping the overall purpose in mind, we can arrive at a comprehensive understanding of the `protocol_core.h` file.
这个头文件 `v8/third_party/inspector_protocol/crdtp/protocol_core.h` 定义了 V8 中用于 Chrome DevTools Protocol (CRDP) 的核心协议基础设施。它提供了一组用于序列化、反序列化以及管理 CRDP 消息的类和模板。

**功能列表:**

1. **数据序列化和反序列化框架:**  它定义了用于将 C++ 数据结构转换为字节流 (序列化) 以及将字节流转换回 C++ 数据结构 (反序列化) 的基础架构。这对于在不同的进程或系统之间传输数据至关重要，特别是对于像 CRDP 这样的协议。

2. **`DeserializerState` 类:**  用于管理反序列化过程的状态。它持有接收到的字节数据，一个 CBOR tokenizer (用于解析数据)，以及错误状态和字段路径信息，以便在反序列化失败时提供有用的错误消息。

3. **`ProtocolTypeTraits` 模板:**  这是一个模板特化结构，为不同的 C++ 数据类型 (例如 `bool`, `int32_t`, `double`, `std::vector`) 提供了定制的序列化和反序列化逻辑。这允许框架以类型安全的方式处理各种数据类型。

4. **`ContainerSerializer` 类:**  用于序列化包含多个字段的对象或容器。它使用 CBOR (Concise Binary Object Representation) 格式进行编码，并提供 `AddField` 方法来添加字段及其值。

5. **`ObjectSerializer` 类:**  提供了一种更高级的方式来序列化对象。它内部使用 `ContainerSerializer`，并管理序列化后的字节数据。

6. **`DeserializerDescriptor` 类:**  描述了如何反序列化特定类型的对象。它包含一个 `Field` 结构体数组，每个结构体定义了一个字段的名称、是否可选以及用于反序列化该字段的函数。

7. **支持 `std::vector` 和 `std::optional` 等容器类型:**  `ProtocolTypeTraits` 针对这些常见容器类型进行了特化，以便可以方便地序列化和反序列化它们。

8. **`DeferredMessage` 类:**  表示一个延迟处理的消息。它可以从可序列化的对象或原始字节跨度创建。它提供了一种创建 `DeserializerState` 的方法，用于稍后反序列化消息。

9. **`DeserializableProtocolObject` 模板类:**  作为可以从字节流反序列化的对象的基类。它提供了静态方法 (例如 `ReadFrom`, `FromBinary`) 来执行反序列化。

10. **`ProtocolObject` 模板类:**  继承自 `DeserializableProtocolObject` 并添加了序列化支持。实现了 `Serializable` 接口，并提供了一个 `Clone` 方法。

11. **`ConvertProtocolValue` 函数模板:**  提供了一种将一个协议值类型转换为另一个协议值类型的便捷方式。

12. **宏定义 (例如 `DECLARE_DESERIALIZATION_SUPPORT`, `DECLARE_SERIALIZATION_SUPPORT`, `V8_CRDTP_BEGIN_DESERIALIZER` 等):**  这些宏简化了在具体的协议类中声明和实现序列化和反序列化逻辑的过程，减少了样板代码。

**关于 `.tq` 扩展名:**

如果 `v8/third_party/inspector_protocol/crdtp/protocol_core.h` 以 `.tq` 结尾，那么它的确是一个 V8 Torque 源代码文件。 Torque 是一种 V8 特有的语言，用于编写 V8 内部的运行时代码，通常用于类型检查和生成高效的 C++ 代码。然而，根据你提供的文件名，它以 `.h` 结尾，因此是一个 C++ 头文件。

**与 JavaScript 的关系 (通过 CRDP):**

CRDP 允许外部工具 (例如 Chrome DevTools) 与 V8 引擎进行通信，以进行调试、性能分析等操作。 `protocol_core.h` 中定义的机制用于序列化和反序列化在 JavaScript 运行时环境和外部工具之间传递的数据。

**JavaScript 示例:**

假设我们需要通过 CRDP 发送一个包含 JavaScript 对象 `{ id: 123, name: "example" }` 的消息。

1. **序列化 (C++ 端):**  `ProtocolObject` 或其派生类会使用 `ContainerSerializer` 将这个对象的信息编码成 CBOR 字节流。例如，可能会有如下的字段添加操作：

   ```c++
   class MyMessage : public v8_crdtp::ProtocolObject<MyMessage> {
    public:
     DECLARE_SERIALIZATION_SUPPORT();

     int id;
     std::string name;
   };

   void MyMessage::AppendSerialized(std::vector<uint8_t>* bytes) const {
     V8_CRDTP_BEGIN_SERIALIZER(MyMessage)
       V8_CRDTP_SERIALIZE_FIELD("id", id);
       V8_CRDTP_SERIALIZE_FIELD("name", name);
     V8_CRDTP_END_SERIALIZER()
   }
   ```

2. **传输 (CRDP 机制):**  生成的字节流会通过 CRDP 协议发送。

3. **反序列化 (JavaScript 端 - DevTools):** DevTools 接收到字节流后，会使用相应的 CRDP 解析器将其转换回 JavaScript 对象 `{ id: 123, name: "example" }`。

反过来，当 DevTools 发送命令到 V8 时，也会发生类似的反序列化 (DevTools -> C++) 和序列化 (C++ -> DevTools) 的过程。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下 C++ 代码使用 `DeserializerDescriptor` 来反序列化一个结构体：

```c++
struct MyData {
  int id;
  std::optional<std::string> description;

  DECLARE_DESERIALIZATION_SUPPORT();
};

const MyData::DeserializerDescriptorType& MyData::deserializer_descriptor() {
  using namespace v8_crdtp;
  static const DeserializerDescriptorType::Field fields[] = {
    V8_CRDTP_DESERIALIZE_FIELD("id", id),
    V8_CRDTP_DESERIALIZE_FIELD_OPT("description", description)
  };
  static const DeserializerDescriptorType s_desc(
      fields, sizeof fields / sizeof fields[0]);
  return s_desc;
}

// 假设输入的 CBOR 字节流表示 {"id": 42, "description": "test"}
std::vector<uint8_t> input_bytes = { /* CBOR 编码的 {"id": 42, "description": "test"} */ };

MyData data;
v8_crdtp::DeserializerState state(input_bytes);
MyData::Deserialize(&state, &data);

// 假设输入的 CBOR 字节流表示 {"id": 100} (没有 "description")
std::vector<uint8_t> input_bytes_optional = { /* CBOR 编码的 {"id": 100} */ };

MyData data_optional;
v8_crdtp::DeserializerState state_optional(input_bytes_optional);
MyData::Deserialize(&state_optional, &data_optional);
```

**假设输入与输出:**

* **输入 1:** CBOR 字节流表示 `{"id": 42, "description": "test"}`
* **输出 1:** `data.id` 将为 `42`， `data.description` 将为 `std::optional<std::string>("test")`。

* **输入 2:** CBOR 字节流表示 `{"id": 100}`
* **输出 2:** `data_optional.id` 将为 `100`， `data_optional.description` 将是一个空的 `std::optional`。

**用户常见的编程错误:**

1. **序列化/反序列化类型不匹配:**  如果 C++ 端的类型与 JavaScript 端期望的类型不一致，会导致反序列化失败或数据错误。例如，C++ 端发送一个整数，而 JavaScript 端尝试将其解析为字符串。

   ```javascript
   // JavaScript 期望接收一个字符串类型的 'value'
   // C++ 代码错误地发送了一个整数
   class MyMessage : public v8_crdtp::ProtocolObject<MyMessage> {
    public:
     DECLARE_SERIALIZATION_SUPPORT();
     int value;
   };

   void MyMessage::AppendSerialized(std::vector<uint8_t>* bytes) const {
     V8_CRDTP_BEGIN_SERIALIZER(MyMessage)
       V8_CRDTP_SERIALIZE_FIELD("value", value); // 错误：发送了 int
     V8_CRDTP_END_SERIALIZER()
   }
   ```

2. **忘记序列化或反序列化某些字段:**  如果在定义 `AppendSerialized` 或 `deserializer_descriptor` 时遗漏了某些字段，这些字段的值将不会被发送或接收。

   ```c++
   // 忘记序列化 'name' 字段
   class MyMessage : public v8_crdtp::ProtocolObject<MyMessage> {
    public:
     DECLARE_SERIALIZATION_SUPPORT();
     int id;
     std::string name;
   };

   void MyMessage::AppendSerialized(std::vector<uint8_t>* bytes) const {
     V8_CRDTP_BEGIN_SERIALIZER(MyMessage)
       V8_CRDTP_SERIALIZE_FIELD("id", id);
       // 错误：忘记序列化 name 字段
     V8_CRDTP_END_SERIALIZER()
   }
   ```

3. **处理可选字段不当:**  在反序列化时，如果没有正确处理可选字段 (使用 `std::optional` 或检查字段是否存在)，可能会导致程序崩溃或逻辑错误。

   ```c++
   struct MyData {
     int id;
     std::string description; // 错误：应该使用 std::optional

     DECLARE_DESERIALIZATION_SUPPORT();
   };

   const MyData::DeserializerDescriptorType& MyData::deserializer_descriptor() {
     using namespace v8_crdtp;
     static const DeserializerDescriptorType::Field fields[] = {
       V8_CRDTP_DESERIALIZE_FIELD("id", id),
       V8_CRDTP_DESERIALIZE_FIELD("description", description) // 如果 "description" 不存在，这里会出错
     };
     static const DeserializerDescriptorType s_desc(
         fields, sizeof fields / sizeof fields[0]);
     return s_desc;
   }
   ```

4. **CBOR 编码错误:**  手动创建或修改 CBOR 字节流时，可能会引入格式错误，导致反序列化失败。

5. **宏定义使用不当:**  `DECLARE_SERIALIZATION_SUPPORT` 和 `DECLARE_DESERIALIZATION_SUPPORT` 宏必须成对使用，并且在定义序列化/反序列化逻辑时需要遵循宏的语法，否则会导致编译错误或运行时错误。

理解 `protocol_core.h` 中的这些概念对于开发和维护 V8 的 CRDP 相关功能至关重要。它提供了一个结构化的方法来处理跨进程或跨系统的数据交换。

Prompt: 
```
这是目录为v8/third_party/inspector_protocol/crdtp/protocol_core.h的一个v8源代码， 请列举一下它的功能, 
如果v8/third_party/inspector_protocol/crdtp/protocol_core.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CRDTP_PROTOCOL_CORE_H_
#define V8_CRDTP_PROTOCOL_CORE_H_

#include <sys/types.h>

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include "cbor.h"
#include "maybe.h"
#include "serializable.h"
#include "span.h"
#include "status.h"

namespace v8_crdtp {

class DeserializerState {
 public:
  using Storage = std::shared_ptr<const std::vector<uint8_t>>;

  // Creates a state from the raw bytes received from the peer.
  explicit DeserializerState(std::vector<uint8_t> bytes);
  // Creates the state from the part of another message.
  DeserializerState(Storage storage, span<uint8_t> span);
  DeserializerState(const DeserializerState& r) = delete;
  DeserializerState(DeserializerState&& r) = default;

  // Registers |error|, unless the tokenizer's status is already an error.
  void RegisterError(Error error);
  // Registers |name| as a segment of the field path.
  void RegisterFieldPath(span<char> name);

  // Produces an error message considering |tokenizer.Status()|,
  // status_, and field_path_.
  std::string ErrorMessage(span<char> message_name) const;
  Status status() const;
  const Storage& storage() const { return storage_; }
  cbor::CBORTokenizer* tokenizer() { return &tokenizer_; }

 private:
  const Storage storage_;
  cbor::CBORTokenizer tokenizer_;
  Status status_;
  std::vector<span<char>> field_path_;
};

template <typename T, typename = void>
struct ProtocolTypeTraits {};

template <>
struct ProtocolTypeTraits<bool> {
  static bool Deserialize(DeserializerState* state, bool* value);
  static void Serialize(bool value, std::vector<uint8_t>* bytes);
};

template <>
struct ProtocolTypeTraits<int32_t> {
  static bool Deserialize(DeserializerState* state, int* value);
  static void Serialize(int value, std::vector<uint8_t>* bytes);
};

template <>
struct ProtocolTypeTraits<double> {
  static bool Deserialize(DeserializerState* state, double* value);
  static void Serialize(double value, std::vector<uint8_t>* bytes);
};

class ContainerSerializer {
 public:
  ContainerSerializer(std::vector<uint8_t>* bytes, uint8_t tag);

  template <typename T>
  void AddField(span<char> field_name, const T& value) {
    cbor::EncodeString8(
        span<uint8_t>(reinterpret_cast<const uint8_t*>(field_name.data()),
                      field_name.size()),
        bytes_);
    ProtocolTypeTraits<T>::Serialize(value, bytes_);
  }
  template <typename T>
  void AddField(span<char> field_name, const std::optional<T>& value) {
    if (!value.has_value()) {
      return;
    }
    AddField(field_name, value.value());
  }

  template <typename T>
  void AddField(span<char> field_name, const detail::PtrMaybe<T>& value) {
    if (!value.has_value()) {
      return;
    }
    AddField(field_name, value.value());
  }

  void EncodeStop();

 private:
  std::vector<uint8_t>* const bytes_;
  cbor::EnvelopeEncoder envelope_;
};

class ObjectSerializer {
 public:
  ObjectSerializer();
  ~ObjectSerializer();

  template <typename T>
  void AddField(span<char> name, const T& field) {
    serializer_.AddField(name, field);
  }
  std::unique_ptr<Serializable> Finish();

 private:
  std::vector<uint8_t> owned_bytes_;
  ContainerSerializer serializer_;
};

class DeserializerDescriptor {
 public:
  struct Field {
    span<char> name;
    bool is_optional;
    bool (*deserializer)(DeserializerState* state, void* obj);
  };

  DeserializerDescriptor(const Field* fields, size_t field_count);

  bool Deserialize(DeserializerState* state, void* obj) const;

 private:
  bool DeserializeField(DeserializerState* state,
                        span<char> name,
                        int* seen_mandatory_fields,
                        void* obj) const;

  const Field* const fields_;
  const size_t field_count_;
  const int mandatory_field_mask_;
};

template <typename T>
struct ProtocolTypeTraits<std::vector<T>> {
  static bool Deserialize(DeserializerState* state, std::vector<T>* value) {
    auto* tokenizer = state->tokenizer();
    if (tokenizer->TokenTag() == cbor::CBORTokenTag::ENVELOPE)
      tokenizer->EnterEnvelope();
    if (tokenizer->TokenTag() != cbor::CBORTokenTag::ARRAY_START) {
      state->RegisterError(Error::CBOR_ARRAY_START_EXPECTED);
      return false;
    }
    assert(value->empty());
    tokenizer->Next();
    for (; tokenizer->TokenTag() != cbor::CBORTokenTag::STOP;
         tokenizer->Next()) {
      value->emplace_back();
      if (!ProtocolTypeTraits<T>::Deserialize(state, &value->back()))
        return false;
    }
    return true;
  }

  static void Serialize(const std::vector<T>& value,
                        std::vector<uint8_t>* bytes) {
    ContainerSerializer container_serializer(
        bytes, cbor::EncodeIndefiniteLengthArrayStart());
    for (const auto& item : value)
      ProtocolTypeTraits<T>::Serialize(item, bytes);
    container_serializer.EncodeStop();
  }
};

template <typename T>
struct ProtocolTypeTraits<std::unique_ptr<std::vector<T>>> {
  static bool Deserialize(DeserializerState* state,
                          std::unique_ptr<std::vector<T>>* value) {
    auto res = std::make_unique<std::vector<T>>();
    if (!ProtocolTypeTraits<std::vector<T>>::Deserialize(state, res.get()))
      return false;
    *value = std::move(res);
    return true;
  }
  static void Serialize(const std::unique_ptr<std::vector<T>>& value,
                        std::vector<uint8_t>* bytes) {
    ProtocolTypeTraits<std::vector<T>>::Serialize(*value, bytes);
  }
};

class DeferredMessage : public Serializable {
 public:
  static std::unique_ptr<DeferredMessage> FromSerializable(
      std::unique_ptr<Serializable> serializeable);
  static std::unique_ptr<DeferredMessage> FromSpan(span<uint8_t> bytes);

  ~DeferredMessage() override = default;
  virtual DeserializerState MakeDeserializer() const = 0;

 protected:
  DeferredMessage() = default;
};

template <>
struct ProtocolTypeTraits<std::unique_ptr<DeferredMessage>> {
  static bool Deserialize(DeserializerState* state,
                          std::unique_ptr<DeferredMessage>* value);
  static void Serialize(const std::unique_ptr<DeferredMessage>& value,
                        std::vector<uint8_t>* bytes);
};

template <typename T>
struct ProtocolTypeTraits<std::optional<T>> {
  static bool Deserialize(DeserializerState* state, std::optional<T>* value) {
    T res;
    if (!ProtocolTypeTraits<T>::Deserialize(state, &res))
      return false;
    *value = std::move(res);
    return true;
  }

  static void Serialize(const std::optional<T>& value,
                        std::vector<uint8_t>* bytes) {
    ProtocolTypeTraits<T>::Serialize(value.value(), bytes);
  }
};

template <typename T>
struct ProtocolTypeTraits<detail::PtrMaybe<T>> {
  static bool Deserialize(DeserializerState* state,
                          detail::PtrMaybe<T>* value) {
    std::unique_ptr<T> res;
    if (!ProtocolTypeTraits<std::unique_ptr<T>>::Deserialize(state, &res))
      return false;
    *value = std::move(res);
    return true;
  }

  static void Serialize(const detail::PtrMaybe<T>& value,
                        std::vector<uint8_t>* bytes) {
    ProtocolTypeTraits<T>::Serialize(value.value(), bytes);
  }
};

template <typename T>
class DeserializableProtocolObject {
 public:
  static StatusOr<std::unique_ptr<T>> ReadFrom(
      const DeferredMessage& deferred_message) {
    auto state = deferred_message.MakeDeserializer();
    if (auto res = Deserialize(&state))
      return StatusOr<std::unique_ptr<T>>(std::move(res));
    return StatusOr<std::unique_ptr<T>>(state.status());
  }

  static StatusOr<std::unique_ptr<T>> ReadFrom(std::vector<uint8_t> bytes) {
    auto state = DeserializerState(std::move(bytes));
    if (auto res = Deserialize(&state))
      return StatusOr<std::unique_ptr<T>>(std::move(res));
    return StatusOr<std::unique_ptr<T>>(state.status());
  }

  // Short-hand for legacy clients. This would swallow any errors, consider
  // using ReadFrom.
  static std::unique_ptr<T> FromBinary(const uint8_t* bytes, size_t size) {
    std::unique_ptr<T> value(new T());
    auto deserializer = DeferredMessage::FromSpan(span<uint8_t>(bytes, size))
                            ->MakeDeserializer();
    std::ignore = Deserialize(&deserializer, value.get());
    return value;
  }

  [[nodiscard]] static bool Deserialize(DeserializerState* state, T* value) {
    return T::deserializer_descriptor().Deserialize(state, value);
  }

 protected:
  // This is for the sake of the macros used by derived classes thay may be in
  // a different namespace;
  using ProtocolType = T;
  using DeserializerDescriptorType = DeserializerDescriptor;
  template <typename U>
  using DeserializableBase = DeserializableProtocolObject<U>;

  DeserializableProtocolObject() = default;
  ~DeserializableProtocolObject() = default;

 private:
  friend struct ProtocolTypeTraits<std::unique_ptr<T>>;

  static std::unique_ptr<T> Deserialize(DeserializerState* state) {
    std::unique_ptr<T> value(new T());
    if (Deserialize(state, value.get()))
      return value;
    return nullptr;
  }
};

template <typename T>
class ProtocolObject : public Serializable,
                       public DeserializableProtocolObject<T> {
 public:
  std::unique_ptr<T> Clone() const {
    std::vector<uint8_t> serialized;
    AppendSerialized(&serialized);
    return T::ReadFrom(std::move(serialized)).value();
  }

 protected:
  using ProtocolType = T;

  ProtocolObject() = default;
};

template <typename T>
struct ProtocolTypeTraits<
    T,
    typename std::enable_if<
        std::is_base_of<ProtocolObject<T>, T>::value>::type> {
  static bool Deserialize(DeserializerState* state, T* value) {
    return T::Deserialize(state, value);
  }

  static void Serialize(const T& value, std::vector<uint8_t>* bytes) {
    value.AppendSerialized(bytes);
  }
};

template <typename T>
struct ProtocolTypeTraits<
    std::unique_ptr<T>,
    typename std::enable_if<
        std::is_base_of<ProtocolObject<T>, T>::value>::type> {
  static bool Deserialize(DeserializerState* state, std::unique_ptr<T>* value) {
    std::unique_ptr<T> res = T::Deserialize(state);
    if (!res)
      return false;
    *value = std::move(res);
    return true;
  }

  static void Serialize(const std::unique_ptr<T>& value,
                        std::vector<uint8_t>* bytes) {
    ProtocolTypeTraits<T>::Serialize(*value, bytes);
  }
};

template <typename T, typename F>
bool ConvertProtocolValue(const F& from, T* to) {
  std::vector<uint8_t> bytes;
  ProtocolTypeTraits<F>::Serialize(from, &bytes);
  auto deserializer =
      DeferredMessage::FromSpan(span<uint8_t>(bytes.data(), bytes.size()))
          ->MakeDeserializer();
  return ProtocolTypeTraits<T>::Deserialize(&deserializer, to);
}

#define DECLARE_DESERIALIZATION_SUPPORT()  \
  friend DeserializableBase<ProtocolType>; \
  static const DeserializerDescriptorType& deserializer_descriptor()

#define DECLARE_SERIALIZATION_SUPPORT()                              \
 public:                                                             \
  void AppendSerialized(std::vector<uint8_t>* bytes) const override; \
                                                                     \
 private:                                                            \
  friend DeserializableBase<ProtocolType>;                           \
  static const DeserializerDescriptorType& deserializer_descriptor()

#define V8_CRDTP_DESERIALIZE_FILED_IMPL(name, field, is_optional)  \
  {                                                                \
    MakeSpan(name), is_optional,                                   \
        [](DeserializerState* __state, void* __obj) -> bool {      \
          return ProtocolTypeTraits<decltype(field)>::Deserialize( \
              __state, &static_cast<ProtocolType*>(__obj)->field); \
        }                                                          \
  }

// clang-format off
#define V8_CRDTP_BEGIN_DESERIALIZER(type)                                      \
  const type::DeserializerDescriptorType& type::deserializer_descriptor() { \
    using namespace v8_crdtp;                                                  \
    static const DeserializerDescriptorType::Field fields[] = {

#define V8_CRDTP_END_DESERIALIZER()                    \
    };                                              \
    static const DeserializerDescriptorType s_desc( \
        fields, sizeof fields / sizeof fields[0]);  \
    return s_desc;                                  \
  }

#define V8_CRDTP_DESERIALIZE_FIELD(name, field) \
  V8_CRDTP_DESERIALIZE_FILED_IMPL(name, field, false)
#define V8_CRDTP_DESERIALIZE_FIELD_OPT(name, field) \
  V8_CRDTP_DESERIALIZE_FILED_IMPL(name, field, true)

#define V8_CRDTP_BEGIN_SERIALIZER(type)                               \
  void type::AppendSerialized(std::vector<uint8_t>* bytes) const { \
    using namespace v8_crdtp;                                         \
    ContainerSerializer __serializer(bytes,                        \
                                     cbor::EncodeIndefiniteLengthMapStart());

#define V8_CRDTP_SERIALIZE_FIELD(name, field) \
    __serializer.AddField(MakeSpan(name), field)

#define V8_CRDTP_END_SERIALIZER() \
    __serializer.EncodeStop();   \
  } class __cddtp_dummy_name
// clang-format on

}  // namespace v8_crdtp

#endif  // V8_CRDTP_PROTOCOL_CORE_H_

"""

```