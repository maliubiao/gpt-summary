Response:
Let's break down the thought process for analyzing the given C++ code.

1. **Understand the Goal:** The first thing to do is read the introductory comments and the question itself. The core purpose is to generate C++ code for debugging V8 objects, allowing inspection of their properties in scenarios where direct memory access isn't possible (like post-mortem debugging). The question asks for functionality, JavaScript relevance, logic examples, and common errors.

2. **Identify Key Components:** Scan the code for major building blocks. I see:
    * **Namespaces:** `v8::internal::torque`. This immediately tells me it's related to Torque, V8's internal language for defining object layouts and built-ins.
    * **Constants:** `kTqObjectOverrideDecls`. This likely holds common method declarations for the generated debug classes.
    * **Enums:** `TypeStorage`. This suggests different ways types might be represented.
    * **Iterators/Ranges:** `ValueTypeFieldIterator`, `ValueTypeFieldsRange`. These are clearly for iterating over struct/bitfield members.
    * **Data Structures:** `DebugFieldType`. This seems important for representing type information in the generated code.
    * **Functions (key generation logic):** `GenerateFieldAddressAccessor`, `GenerateFieldValueAccessor`, `GenerateGetPropsChunkForField`, `GenerateClassDebugReader`. These are the workhorses of the code generation.
    * **Top-Level Function:** `ImplementationVisitor::GenerateClassDebugReaders`. This orchestrates the generation process for all classes.

3. **Analyze Core Functionality (Code Generation):**  The core of the file is about generating C++ code. The `GenerateClassDebugReader` function is central. It iterates through `TypeOracle::GetClasses()` (meaning it's processing V8's object definitions). For each class, it generates a corresponding `TqFoo` class. These `TqFoo` classes have methods to:
    * Get properties (`GetProperties`)
    * Get the class name (`GetName`)
    * Support a visitor pattern (`Visit`)
    * Check inheritance (`IsSuperclassOf`)
    * Access individual fields (`GenerateFieldAddressAccessor`, `GenerateFieldValueAccessor`).

4. **Examine Data Structures and Helpers:**
    * `DebugFieldType`:  This class manages the complexities of representing types in the debug code. It handles tagged vs. untagged pointers and provides different representations for different contexts (debug helper vs. full V8 symbols). The `GetValueType`, `GetOriginalType`, and `GetTypeString` methods are key.
    * `ValueTypeFieldsRange`: This simplifies iterating over fields within structs and bitfields, handling different layout scenarios.

5. **Consider the Output:**  The comments mention generating `.h` and `.cc` files. The generated `TqFoo` classes aim to provide a way to inspect object layouts and field values when directly accessing memory isn't possible. The visitor pattern (`TqObjectVisitor`) allows for custom actions when traversing the object hierarchy.

6. **Relate to Torque:** The file is in `v8/src/torque`. The comment about `.tq` files confirms that this code *generates* C++ from Torque definitions. Torque is used to define the structure and layout of V8 objects. This file takes those definitions and creates debug readers.

7. **Identify JavaScript Relevance:**  Since Torque defines the structure of V8's internal objects, which are the building blocks of JavaScript objects, there's a strong indirect connection. The generated code helps debug the *implementation* of JavaScript objects.

8. **Develop Examples:** Now, put the pieces together with examples:
    * **JavaScript Example:** A simple JavaScript object shows what the underlying V8 objects represent. Explain that the debug reader helps inspect the internal representation of that object.
    * **Logic Example:**  Choose a simple scenario, like a class with a few fields. Show the generated `GetProperties` output for that class, highlighting how field names, types, and addresses are represented. Think about the different cases (tagged, untagged, struct).
    * **Common Errors:** Focus on the problems this code tries to solve or assumptions it makes. Forgetting includes (mentioned in a comment), incorrect constexpr type names, and assumptions about memory layout are good candidates.

9. **Refine and Organize:** Structure the answer logically. Start with the main functionality, then delve into details, and finally address the specific points in the question (JavaScript, logic, errors). Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This seems like it's directly running JavaScript."  **Correction:**  The namespaces and Torque connection indicate it's about V8 internals, not executing JS.
* **Considering the "visitor":**  Realize the visitor pattern allows for extensible debugging. The generated `VisitFoo` methods are crucial for this.
* **Focusing too much on individual functions:**  Shift focus to the overall purpose and how the functions contribute to that goal. `GenerateClassDebugReader` is the orchestrator.
* **JavaScript connection too vague:**  Make the connection explicit: Torque defines V8 object structure, which is used for JavaScript objects. The debug reader helps inspect *that* structure.

By following this thought process, breaking down the code, understanding its context, and connecting it to the questions asked, you can arrive at a comprehensive and accurate explanation.
好的，让我们来分析一下 `v8/src/torque/class-debug-reader-generator.cc` 这个文件的功能。

**主要功能：生成用于调试 V8 对象的 C++ 代码**

这个文件的主要职责是根据 Torque 定义的类（ClassType），生成 C++ 代码，这些代码可以帮助在调试场景下（例如，崩溃转储分析、远程调试）读取和检查 V8 对象的属性。

**详细功能分解：**

1. **生成 `TqFoo` 类:** 对于每个 Torque 定义的类 `Foo`，这个文件会生成一个对应的 C++ 类 `TqFoo`。`TqFoo` 类继承自其父类的 `Tq` 版本（例如，`TqParentOfFoo`）或 `TqObject`。

2. **提供属性访问方法:** `TqFoo` 类会包含以下方法，用于访问和描述对象的属性：
   - `GetProperties(d::MemoryAccessor accessor)`:  返回一个包含对象所有属性信息的 `std::vector`。每个属性信息都封装在一个 `ObjectProperty` 对象中，包含属性名、类型、地址、大小等。
   - `GetName() const`: 返回类的名称，例如 `"v8::internal::Foo"`。
   - `Visit(TqObjectVisitor* visitor) const`: 支持访问者模式，允许对 `TqFoo` 对象执行自定义操作。
   - `IsSuperclassOf(const TqObject* other) const`: 判断当前类是否是另一个 `TqObject` 的超类。
   - `Get[FieldName]Address() const`:  返回特定字段的内存地址。
   - `Get[FieldName]Value(d::MemoryAccessor accessor, ... ) const`: 使用提供的 `MemoryAccessor` 函数指针从 debuggee 的内存中读取字段的值。对于数组类型的字段，会包含一个 `offset` 参数。

3. **处理不同类型的字段:**
   - **基本类型:**  直接读取内存中的值。
   - **Tagged 类型:** 特殊处理，可能会进行解压缩（`EnsureDecompressed`），因为 V8 会对指针进行压缩优化。
   - **结构体 (Struct):**  递归地处理结构体内部的字段，生成 `StructProperty` 信息。
   - **位域 (BitField):**  处理位域字段的偏移和位数。
   - **数组:**  会尝试读取数组的长度，并生成相应的属性信息，`PropertyKind` 会指示数组长度是否已知。

4. **生成 `TqObjectVisitor` 类:** 定义了一个抽象基类 `TqObjectVisitor`，其中包含了针对每个 Torque 类的 `VisitFoo(const TqFoo* object)` 虚方法。这允许用户自定义访问器，只需重写他们关心的类的访问方法即可。

5. **使用 `MemoryAccessor` 抽象内存访问:**  通过 `d::MemoryAccessor` 函数指针来读取 debuggee 的内存，这使得生成的代码可以用于多种调试场景，而无需直接访问当前进程的内存。

**如果 `v8/src/torque/class-debug-reader-generator.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码**

你的理解是正确的。如果文件以 `.tq` 结尾，它通常表示这是一个 Torque 源代码文件。但是，`class-debug-reader-generator.cc` 本身是一个 C++ 文件，它的作用是 *生成* 其他 C++ 代码，而这些生成的代码是基于 Torque 的类定义。

**与 Javascript 的功能关系：**

V8 是一个 JavaScript 引擎，而 Torque 是 V8 内部用于定义对象布局、内置函数等的语言。  `class-debug-reader-generator.cc` 生成的 C++ 代码，其目的是为了方便调试 V8 内部的各种对象。这些对象是 JavaScript 运行时环境的基础。

**JavaScript 示例：**

假设在 Torque 中定义了一个名为 `MyObject` 的类，它包含一个名为 `value` 的属性，类型为数字：

```torque
class MyObject extends HeapObject {
  value: Number;
}
```

`class-debug-reader-generator.cc` 会生成一个对应的 `TqMyObject` 类，其中可能包含类似这样的方法：

```c++
class TqMyObject : public TqHeapObject {
 public:
  inline TqMyObject(uintptr_t address) : TqHeapObject(address) {}

  Value<uintptr_t> GetValueValue(d::MemoryAccessor accessor) const;
  // ... 其他方法
};

Value<uintptr_t> TqMyObject::GetValueValue(d::MemoryAccessor accessor) const {
  i::Tagged_t value{};
  d::MemoryAccessResult validity = accessor(
      GetvalueAddress(), // 假设生成了 GetvalueAddress() 方法
      reinterpret_cast<uint8_t*>(&value),
      sizeof(value));
  return {validity, EnsureDecompressed(value, address_)};
}
```

在 JavaScript 中，你可以创建 `MyObject` 的实例：

```javascript
let myObject = { value: 42 }; // 这只是一个逻辑上的对应，实际 V8 内部对象结构复杂得多
```

当你在调试 V8 的时候，例如遇到了一个 `MyObject` 的实例，你可以使用生成的 `TqMyObject` 类来检查其内部的 `value` 属性：

```c++
// 假设 'object_address' 是 MyObject 实例的内存地址
TqMyObject tqMyObject(object_address);

// 定义一个内存访问器，用于从 debuggee 的内存中读取数据
auto memory_accessor = [](uintptr_t address, uint8_t* buffer, size_t size) -> d::MemoryAccessResult {
  // ... 实现从目标内存读取数据的逻辑
  return d::MemoryAccessResult::kOk; // 假设读取成功
};

auto value_result = tqMyObject.GetValueValue(memory_accessor);
if (value_result.validity == d::MemoryAccessResult::kOk) {
  uintptr_t value = value_result.value;
  // value 现在包含了 myObject.value 的内部表示
}
```

**代码逻辑推理 (假设输入与输出)：**

**假设输入：**

一个简单的 Torque 类定义：

```torque
class Point extends HeapObject {
  x: Smi;
  y: Smi;
}
```

**期望输出（`TqPoint` 类的部分代码）：**

```c++
class TqPoint : public TqHeapObject {
 public:
  inline TqPoint(uintptr_t address) : TqHeapObject(address) {}

  Value<uintptr_t> GetXValue(d::MemoryAccessor accessor) const;
  Value<uintptr_t> GetYValue(d::MemoryAccessor accessor) const;
  uintptr_t GetXAddress() const;
  uintptr_t GetYAddress() const;
  // ... 其他方法
};

uintptr_t TqPoint::GetXAddress() const {
  return address_ - i::kHeapObjectTag + /* x 的偏移量 */;
}

Value<uintptr_t> TqPoint::GetXValue(d::MemoryAccessor accessor) const {
  i::Tagged_t value{};
  d::MemoryAccessResult validity = accessor(
      GetXAddress(),
      reinterpret_cast<uint8_t*>(&value),
      sizeof(value));
  return {validity, EnsureDecompressed(value, address_)};
}

// GetYAddress 和 GetYValue 类似
```

**涉及用户常见的编程错误（针对使用生成的调试代码的用户）：**

1. **忘记实现或提供正确的 `MemoryAccessor`:**  `MemoryAccessor` 是从 debuggee 内存中读取数据的关键。如果用户提供的 `MemoryAccessor` 实现不正确，或者根本没有提供，会导致读取到的数据是错误的。

   ```c++
   // 错误示例：没有实现 MemoryAccessor
   auto memory_accessor = nullptr;
   TqMyObject tqMyObject(some_address);
   // tqMyObject.GetValueValue(memory_accessor); // 会崩溃或产生错误
   ```

2. **假设固定的内存布局:**  V8 的内部对象布局可能会发生变化。用户不应该假设特定字段的偏移量是固定不变的，而应该依赖生成的 `Get[FieldName]Address()` 方法。

3. **不处理 `MemoryAccessResult`:** 从 `MemoryAccessor` 返回的 `MemoryAccessResult` 指示了内存读取是否成功。用户应该检查这个结果，以处理内存不可访问的情况。

   ```c++
   TqMyObject tqMyObject(some_address);
   auto value_result = tqMyObject.GetValueValue(my_memory_accessor);
   if (value_result.validity != d::MemoryAccessResult::kOk) {
     // 处理内存读取失败的情况
     std::cerr << "Failed to read value from memory." << std::endl;
   } else {
     uintptr_t value = value_result.value;
     // 使用读取到的值
   }
   ```

4. **类型转换错误:**  虽然生成的代码尝试提供正确的类型，但在使用读取到的原始数据时，用户仍然可能犯类型转换的错误。

5. **在不适用的场景下使用:**  这些生成的调试代码主要用于离线调试或远程调试，不应该在正常的 V8 运行时环境中使用，因为它依赖于外部的内存访问机制。

总而言之，`v8/src/torque/class-debug-reader-generator.cc` 是一个非常重要的代码生成器，它为 V8 的调试提供了强大的支持，允许开发者在无法直接访问对象内存的情况下，仍然能够理解和分析 V8 内部对象的状态。

### 提示词
```
这是目录为v8/src/torque/class-debug-reader-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/class-debug-reader-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/flags/flags.h"
#include "src/torque/implementation-visitor.h"
#include "src/torque/type-oracle.h"

namespace v8::internal::torque {

constexpr char kTqObjectOverrideDecls[] =
    R"(  std::vector<std::unique_ptr<ObjectProperty>> GetProperties(
      d::MemoryAccessor accessor) const override;
  const char* GetName() const override;
  void Visit(TqObjectVisitor* visitor) const override;
  bool IsSuperclassOf(const TqObject* other) const override;
)";

namespace {
enum TypeStorage {
  kAsStoredInHeap,
  kUncompressed,
};

// An iterator for use in ValueTypeFieldsRange.
class ValueTypeFieldIterator {
 public:
  ValueTypeFieldIterator(const Type* type, size_t index)
      : type_(type), index_(index) {}
  struct Result {
    NameAndType name_and_type;
    SourcePosition pos;
    size_t offset_bytes;
    int num_bits;
    int shift_bits;
  };
  const Result operator*() const {
    if (auto struct_type = type_->StructSupertype()) {
      const auto& field = (*struct_type)->fields()[index_];
      return {field.name_and_type, field.pos, *field.offset, 0, 0};
    }
    const Type* type = type_;
    int bitfield_start_offset = 0;
    if (const auto type_wrapped_in_smi =
            Type::MatchUnaryGeneric(type_, TypeOracle::GetSmiTaggedGeneric())) {
      type = *type_wrapped_in_smi;
      bitfield_start_offset = TargetArchitecture::SmiTagAndShiftSize();
    }
    if (const BitFieldStructType* bit_field_struct_type =
            BitFieldStructType::DynamicCast(type)) {
      const auto& field = bit_field_struct_type->fields()[index_];
      return {field.name_and_type, field.pos, 0, field.num_bits,
              field.offset + bitfield_start_offset};
    }
    UNREACHABLE();
  }
  ValueTypeFieldIterator& operator++() {
    ++index_;
    return *this;
  }
  bool operator==(const ValueTypeFieldIterator& other) const {
    return type_ == other.type_ && index_ == other.index_;
  }
  bool operator!=(const ValueTypeFieldIterator& other) const {
    return !(*this == other);
  }

 private:
  const Type* type_;
  size_t index_;
};

// A way to iterate over the fields of structs or bitfield structs. For other
// types, the iterators returned from begin() and end() are immediately equal.
class ValueTypeFieldsRange {
 public:
  explicit ValueTypeFieldsRange(const Type* type) : type_(type) {}
  ValueTypeFieldIterator begin() { return {type_, 0}; }
  ValueTypeFieldIterator end() {
    size_t index = 0;
    std::optional<const StructType*> struct_type = type_->StructSupertype();
    if (struct_type && *struct_type != TypeOracle::GetFloat64OrHoleType()) {
      index = (*struct_type)->fields().size();
    }
    const Type* type = type_;
    if (const auto type_wrapped_in_smi =
            Type::MatchUnaryGeneric(type_, TypeOracle::GetSmiTaggedGeneric())) {
      type = *type_wrapped_in_smi;
    }
    if (const BitFieldStructType* bit_field_struct_type =
            BitFieldStructType::DynamicCast(type)) {
      index = bit_field_struct_type->fields().size();
    }
    return {type_, index};
  }

 private:
  const Type* type_;
};

// A convenient way to keep track of several different ways that we might need
// to represent a field's type in the generated C++.
class DebugFieldType {
 public:
  explicit DebugFieldType(const Field& field)
      : name_and_type_(field.name_and_type), pos_(field.pos) {}
  DebugFieldType(const NameAndType& name_and_type, const SourcePosition& pos)
      : name_and_type_(name_and_type), pos_(pos) {}

  bool IsTagged() const {
    return name_and_type_.type->IsSubtypeOf(TypeOracle::GetTaggedType());
  }

  // Returns the type that should be used for this field's value within code
  // that is compiled as part of the debug helper library. In particular, this
  // simplifies any tagged type to a plain uintptr_t because the debug helper
  // compiles without most of the V8 runtime code.
  std::string GetValueType(TypeStorage storage) const {
    if (IsTagged()) {
      return storage == kAsStoredInHeap ? "i::Tagged_t" : "uintptr_t";
    }

    // We can't emit a useful error at this point if the constexpr type name is
    // wrong, but we can include a comment that might be helpful.
    return GetOriginalType(storage) +
           " /*Failing? Ensure constexpr type name is correct, and the "
           "necessary #include is in any .tq file*/";
  }

  // Returns the type that should be used to represent a field's type to
  // debugging tools that have full V8 symbols. The types returned from this
  // method are resolveable in the v8::internal namespace and may refer to
  // object types that are not included in the compilation of the debug helper
  // library.
  std::string GetOriginalType(TypeStorage storage) const {
    if (name_and_type_.type->StructSupertype()) {
      // There's no meaningful type we could use here, because the V8 symbols
      // don't have any definition of a C++ struct matching this struct type.
      return "";
    }
    if (IsTagged()) {
      std::optional<const ClassType*> field_class_type =
          name_and_type_.type->ClassSupertype();
      std::string result =
          "v8::internal::" +
          (field_class_type.has_value()
               ? (*field_class_type)->GetGeneratedTNodeTypeName()
               : "Object");
      if (storage == kAsStoredInHeap) {
        result = "v8::internal::TaggedMember<" + result + ">";
      }
      return result;
    }
    return name_and_type_.type->GetConstexprGeneratedTypeName();
  }

  // Returns a C++ expression that evaluates to a string (type `const char*`)
  // containing the name of the field's type. The types returned from this
  // method are resolveable in the v8::internal namespace and may refer to
  // object types that are not included in the compilation of the debug helper
  // library.
  std::string GetTypeString(TypeStorage storage) const {
    if (IsTagged() || name_and_type_.type->IsStructType()) {
      // Wrap up the original type in a string literal.
      return "\"" + GetOriginalType(storage) + "\"";
    }

    // We require constexpr type names to be resolvable in the v8::internal
    // namespace, according to the contract in debug-helper.h. In order to
    // verify at compile time that constexpr type names are resolvable, we use
    // the type name as a dummy template parameter to a function that just
    // returns its parameter.
    return "CheckTypeName<" + GetValueType(storage) + ">(\"" +
           GetOriginalType(storage) + "\")";
  }

  // Returns the field's size in bytes.
  size_t GetSize() const {
    auto opt_size = SizeOf(name_and_type_.type);
    if (!opt_size.has_value()) {
      Error("Size required for type ", name_and_type_.type->ToString())
          .Position(pos_);
      return 0;
    }
    return std::get<0>(*opt_size);
  }

  // Returns the name of the function for getting this field's address.
  std::string GetAddressGetter() {
    return "Get" + CamelifyString(name_and_type_.name) + "Address";
  }

 private:
  NameAndType name_and_type_;
  SourcePosition pos_;
};

// Emits a function to get the address of a field within a class, based on the
// member variable {address_}, which is a tagged pointer. Example
// implementation:
//
// uintptr_t TqFixedArray::GetObjectsAddress() const {
//   return address_ - i::kHeapObjectTag + 16;
// }
void GenerateFieldAddressAccessor(const Field& field,
                                  const std::string& class_name,
                                  std::ostream& h_contents,
                                  std::ostream& cc_contents) {
  DebugFieldType debug_field_type(field);

  const std::string address_getter = debug_field_type.GetAddressGetter();

  h_contents << "  uintptr_t " << address_getter << "() const;\n";
  cc_contents << "\nuintptr_t Tq" << class_name << "::" << address_getter
              << "() const {\n";
  cc_contents << "  return address_ - i::kHeapObjectTag + " << *field.offset
              << ";\n";
  cc_contents << "}\n";
}

// Emits a function to get the value of a field, or the value from an indexed
// position within an array field, based on the member variable {address_},
// which is a tagged pointer, and the parameter {accessor}, a function pointer
// that allows for fetching memory from the debuggee. The returned result
// includes both a "validity", indicating whether the memory could be fetched,
// and the fetched value. If the field contains tagged data, then these
// functions call EnsureDecompressed to expand compressed data. Example:
//
// Value<uintptr_t> TqMap::GetPrototypeValue(d::MemoryAccessor accessor) const {
//   i::Tagged_t value{};
//   d::MemoryAccessResult validity = accessor(
//       GetPrototypeAddress(),
//       reinterpret_cast<uint8_t*>(&value),
//       sizeof(value));
//   return {validity, EnsureDecompressed(value, address_)};
// }
//
// For array fields, an offset parameter is included. Example:
//
// Value<uintptr_t> TqFixedArray::GetObjectsValue(d::MemoryAccessor accessor,
//                                                size_t offset) const {
//   i::Tagged_t value{};
//   d::MemoryAccessResult validity = accessor(
//       GetObjectsAddress() + offset * sizeof(value),
//       reinterpret_cast<uint8_t*>(&value),
//       sizeof(value));
//   return {validity, EnsureDecompressed(value, address_)};
// }
void GenerateFieldValueAccessor(const Field& field,
                                const std::string& class_name,
                                std::ostream& h_contents,
                                std::ostream& cc_contents) {
  // Currently not implemented for struct fields.
  if (field.name_and_type.type->StructSupertype()) return;

  DebugFieldType debug_field_type(field);

  const std::string address_getter = debug_field_type.GetAddressGetter();
  const std::string field_getter =
      "Get" + CamelifyString(field.name_and_type.name) + "Value";

  std::string index_param;
  std::string index_offset;
  if (field.index) {
    index_param = ", size_t offset";
    index_offset = " + offset * sizeof(value)";
  }

  std::string field_value_type = debug_field_type.GetValueType(kUncompressed);
  h_contents << "  Value<" << field_value_type << "> " << field_getter
             << "(d::MemoryAccessor accessor " << index_param << ") const;\n";
  cc_contents << "\nValue<" << field_value_type << "> Tq" << class_name
              << "::" << field_getter << "(d::MemoryAccessor accessor"
              << index_param << ") const {\n";
  cc_contents << "  " << debug_field_type.GetValueType(kAsStoredInHeap)
              << " value{};\n";
  cc_contents << "  d::MemoryAccessResult validity = accessor("
              << address_getter << "()" << index_offset
              << ", reinterpret_cast<uint8_t*>(&value), sizeof(value));\n";
#ifdef V8_MAP_PACKING
  if (field_getter == "GetMapValue") {
    cc_contents << "  value = i::MapWord::Unpack(value);\n";
  }
#endif
  cc_contents << "  return {validity, "
              << (debug_field_type.IsTagged()
                      ? "EnsureDecompressed(value, address_)"
                      : "value")
              << "};\n";
  cc_contents << "}\n";
}

// Emits a portion of the member function GetProperties that is responsible for
// adding data about the current field to a result vector called "result".
// Example output:
//
// std::vector<std::unique_ptr<StructProperty>> prototype_struct_field_list;
// result.push_back(std::make_unique<ObjectProperty>(
//     "prototype",                                     // Field name
//     "v8::internal::HeapObject",                      // Field type
//     "v8::internal::HeapObject",                      // Decompressed type
//     GetPrototypeAddress(),                           // Field address
//     1,                                               // Number of values
//     8,                                               // Size of value
//     std::move(prototype_struct_field_list),          // Struct fields
//     d::PropertyKind::kSingle));                      // Field kind
//
// In builds with pointer compression enabled, the field type for tagged values
// is "v8::internal::TaggedValue" (a four-byte class) and the decompressed type
// is a normal Object subclass that describes the expanded eight-byte type.
//
// If the field is an array, then its length is fetched from the debuggee. This
// could fail if the debuggee has incomplete memory, so the "validity" from that
// fetch is used to determine the result PropertyKind, which will say whether
// the array's length is known.
//
// If the field's type is a struct, then a local variable is created and filled
// with descriptions of each of the struct's fields. The type and decompressed
// type in the ObjectProperty are set to the empty string, to indicate to the
// caller that the struct fields vector should be used instead.
//
// The following example is an array of structs, so it uses both of the optional
// components described above:
//
// std::vector<std::unique_ptr<StructProperty>> descriptors_struct_field_list;
// descriptors_struct_field_list.push_back(std::make_unique<StructProperty>(
//     "key",                                // Struct field name
//     "v8::internal::PrimitiveHeapObject",  // Struct field type
//     "v8::internal::PrimitiveHeapObject",  // Struct field decompressed type
//     0,                                    // Byte offset within struct data
//     0,                                    // Bitfield size (0=not a bitfield)
//     0));                                  // Bitfield shift
// // The line above is repeated for other struct fields. Omitted here.
// // Fetch the slice.
// auto indexed_field_slice_descriptors =
//     TqDebugFieldSliceDescriptorArrayDescriptors(accessor, address_);
// if (indexed_field_slice_descriptors.validity == d::MemoryAccessResult::kOk) {
//   result.push_back(std::make_unique<ObjectProperty>(
//     "descriptors",                                 // Field name
//     "",                                            // Field type
//     "",                                            // Decompressed type
//     address_ - i::kHeapObjectTag +
//     std::get<1>(indexed_field_slice_descriptors.value), // Field address
//     std::get<2>(indexed_field_slice_descriptors.value), // Number of values
//     12,                                            // Size of value
//     std::move(descriptors_struct_field_list),      // Struct fields
//     GetArrayKind(indexed_field_slice_descriptors.validity)));  // Field kind
// }
void GenerateGetPropsChunkForField(const Field& field,
                                   std::ostream& get_props_impl,
                                   std::string class_name) {
  DebugFieldType debug_field_type(field);

  // If the current field is a struct or bitfield struct, create a vector
  // describing its fields. Otherwise this vector will be empty.
  std::string struct_field_list =
      field.name_and_type.name + "_struct_field_list";
  get_props_impl << "  std::vector<std::unique_ptr<StructProperty>> "
                 << struct_field_list << ";\n";
  for (const auto& struct_field :
       ValueTypeFieldsRange(field.name_and_type.type)) {
    DebugFieldType struct_field_type(struct_field.name_and_type,
                                     struct_field.pos);
    get_props_impl << "  " << struct_field_list
                   << ".push_back(std::make_unique<StructProperty>(\""
                   << struct_field.name_and_type.name << "\", "
                   << struct_field_type.GetTypeString(kAsStoredInHeap) << ", "
                   << struct_field.offset_bytes << ", " << struct_field.num_bits
                   << ", " << struct_field.shift_bits << "));\n";
  }
  struct_field_list = "std::move(" + struct_field_list + ")";

  // The number of values and property kind for non-indexed properties:
  std::string count_value = "1";
  std::string property_kind = "d::PropertyKind::kSingle";

  // If the field is indexed, emit a fetch of the array length, and change
  // count_value and property_kind to be the correct values for an array.
  if (field.index) {
    std::string indexed_field_slice =
        "indexed_field_slice_" + field.name_and_type.name;
    get_props_impl << "  auto " << indexed_field_slice << " = "
                   << "TqDebugFieldSlice" << class_name
                   << CamelifyString(field.name_and_type.name)
                   << "(accessor, address_);\n";
    std::string validity = indexed_field_slice + ".validity";
    std::string value = indexed_field_slice + ".value";
    property_kind = "GetArrayKind(" + validity + ")";

    get_props_impl << "  if (" << validity
                   << " == d::MemoryAccessResult::kOk) {\n"
                   << "    result.push_back(std::make_unique<ObjectProperty>(\""
                   << field.name_and_type.name << "\", "
                   << debug_field_type.GetTypeString(kAsStoredInHeap) << ", "
                   << "address_ - i::kHeapObjectTag + std::get<1>(" << value
                   << "), "
                   << "std::get<2>(" << value << ")"
                   << ", " << debug_field_type.GetSize() << ", "
                   << struct_field_list << ", " << property_kind << "));\n"
                   << "  }\n";
    return;
  }
  get_props_impl << "  result.push_back(std::make_unique<ObjectProperty>(\""
                 << field.name_and_type.name << "\", "
                 << debug_field_type.GetTypeString(kAsStoredInHeap) << ", "
                 << debug_field_type.GetAddressGetter() << "(), " << count_value
                 << ", " << debug_field_type.GetSize() << ", "
                 << struct_field_list << ", " << property_kind << "));\n";
}

// For any Torque-defined class Foo, this function generates a class TqFoo which
// allows for convenient inspection of objects of type Foo in a crash dump or
// time travel session (where we can't just run the object printer). The
// generated class looks something like this:
//
// class TqFoo : public TqParentOfFoo {
//  public:
//   // {address} is an uncompressed tagged pointer.
//   inline TqFoo(uintptr_t address) : TqParentOfFoo(address) {}
//
//   // Creates and returns a list of this object's properties.
//   std::vector<std::unique_ptr<ObjectProperty>> GetProperties(
//       d::MemoryAccessor accessor) const override;
//
//   // Returns the name of this class, "v8::internal::Foo".
//   const char* GetName() const override;
//
//   // Visitor pattern; implementation just calls visitor->VisitFoo(this).
//   void Visit(TqObjectVisitor* visitor) const override;
//
//   // Returns whether Foo is a superclass of the other object's type.
//   bool IsSuperclassOf(const TqObject* other) const override;
//
//   // Field accessors omitted here (see other comments above).
// };
//
// Four output streams are written:
//
// h_contents:  A header file which gets the class definition above.
// cc_contents: A cc file which gets implementations of that class's members.
// visitor:     A stream that is accumulating the definition of the class
//              TqObjectVisitor. Each class Foo gets its own virtual method
//              VisitFoo in TqObjectVisitor.
void GenerateClassDebugReader(const ClassType& type, std::ostream& h_contents,
                              std::ostream& cc_contents, std::ostream& visitor,
                              std::unordered_set<const ClassType*>* done) {
  // Make sure each class only gets generated once.
  if (!done->insert(&type).second) return;
  const ClassType* super_type = type.GetSuperClass();

  // We must emit the classes in dependency order. If the super class hasn't
  // been emitted yet, go handle it first.
  if (super_type != nullptr) {
    GenerateClassDebugReader(*super_type, h_contents, cc_contents, visitor,
                             done);
  }

  // Classes with undefined layout don't grant any particular value here and may
  // not correspond with actual C++ classes, so skip them.
  if (type.HasUndefinedLayout()) return;

  const std::string name = type.name();
  const std::string super_name =
      super_type == nullptr ? "Object" : super_type->name();
  h_contents << "\nclass Tq" << name << " : public Tq" << super_name << " {\n";
  h_contents << " public:\n";
  h_contents << "  inline Tq" << name << "(uintptr_t address) : Tq"
             << super_name << "(address) {}\n";
  h_contents << kTqObjectOverrideDecls;

  cc_contents << "\nconst char* Tq" << name << "::GetName() const {\n";
  cc_contents << "  return \"v8::internal::" << name << "\";\n";
  cc_contents << "}\n";

  cc_contents << "\nvoid Tq" << name
              << "::Visit(TqObjectVisitor* visitor) const {\n";
  cc_contents << "  visitor->Visit" << name << "(this);\n";
  cc_contents << "}\n";

  cc_contents << "\nbool Tq" << name
              << "::IsSuperclassOf(const TqObject* other) const {\n";
  cc_contents
      << "  return GetName() != other->GetName() && dynamic_cast<const Tq"
      << name << "*>(other) != nullptr;\n";
  cc_contents << "}\n";

  // By default, the visitor method for this class just calls the visitor method
  // for this class's parent. This allows custom visitors to only override a few
  // classes they care about without needing to know about the entire hierarchy.
  visitor << "  virtual void Visit" << name << "(const Tq" << name
          << "* object) {\n";
  visitor << "    Visit" << super_name << "(object);\n";
  visitor << "  }\n";

  std::stringstream get_props_impl;

  for (const Field& field : type.fields()) {
    if (field.name_and_type.type == TypeOracle::GetVoidType()) continue;
    if (field.offset.has_value()) {
      GenerateFieldAddressAccessor(field, name, h_contents, cc_contents);
      GenerateFieldValueAccessor(field, name, h_contents, cc_contents);
    }
    GenerateGetPropsChunkForField(field, get_props_impl, name);
  }

  h_contents << "};\n";

  cc_contents << "\nstd::vector<std::unique_ptr<ObjectProperty>> Tq" << name
              << "::GetProperties(d::MemoryAccessor accessor) const {\n";
  // Start by getting the fields from the parent class.
  cc_contents << "  std::vector<std::unique_ptr<ObjectProperty>> result = Tq"
              << super_name << "::GetProperties(accessor);\n";
  // Then add the fields from this class.
  cc_contents << get_props_impl.str();
  cc_contents << "  return result;\n";
  cc_contents << "}\n";
}
}  // namespace

void ImplementationVisitor::GenerateClassDebugReaders(
    const std::string& output_directory) {
  const std::string file_name = "class-debug-readers";
  std::stringstream h_contents;
  std::stringstream cc_contents;
  h_contents << "// Provides the ability to read object properties in\n";
  h_contents << "// postmortem or remote scenarios, where the debuggee's\n";
  h_contents << "// memory is not part of the current process's address\n";
  h_contents << "// space and must be read using a callback function.\n\n";
  {
    IncludeGuardScope include_guard(h_contents, file_name + ".h");

    h_contents << "#include <cstdint>\n";
    h_contents << "#include <vector>\n\n";

    for (const std::string& include_path : GlobalContext::CppIncludes()) {
      h_contents << "#include " << StringLiteralQuote(include_path) << "\n";
    }

    h_contents
        << "\n#include \"tools/debug_helper/debug-helper-internal.h\"\n\n";

    const char* kWingdiWorkaround =
        "// Unset a wingdi.h macro that causes conflicts.\n"
        "#ifdef GetBValue\n"
        "#undef GetBValue\n"
        "#endif\n\n";

    h_contents << kWingdiWorkaround;

    cc_contents << "#include \"torque-generated/" << file_name << ".h\"\n\n";
    cc_contents << "#include \"src/objects/all-objects-inl.h\"\n";
    cc_contents << "#include \"torque-generated/debug-macros.h\"\n\n";
    cc_contents << kWingdiWorkaround;
    cc_contents << "namespace i = v8::internal;\n\n";

    NamespaceScope h_namespaces(h_contents,
                                {"v8", "internal", "debug_helper_internal"});
    NamespaceScope cc_namespaces(cc_contents,
                                 {"v8", "internal", "debug_helper_internal"});

    std::stringstream visitor;
    visitor << "\nclass TqObjectVisitor {\n";
    visitor << " public:\n";
    visitor << "  virtual void VisitObject(const TqObject* object) {}\n";

    std::unordered_set<const ClassType*> done;
    for (const ClassType* type : TypeOracle::GetClasses()) {
      GenerateClassDebugReader(*type, h_contents, cc_contents, visitor, &done);
    }

    visitor << "};\n";
    h_contents << visitor.str();
  }
  WriteFile(output_directory + "/" + file_name + ".h", h_contents.str());
  WriteFile(output_directory + "/" + file_name + ".cc", cc_contents.str());
}

}  // namespace v8::internal::torque
```