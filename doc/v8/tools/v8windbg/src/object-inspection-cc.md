Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt's questions.

1. **Initial Scan and Overall Purpose:**  The first thing I do is scan the code for keywords, class names, and function names that give hints about its purpose. I see things like `V8CachedObject`, `V8HeapObject`, `Property`, `IndexedFieldData`, `V8ObjectDataModel`, `InspectV8ObjectMethod`. The file path `v8/tools/v8windbg/src/` strongly suggests this is related to debugging V8 using WinDbg. The "object-inspection" part of the filename further narrows it down to inspecting the properties and structure of V8 objects within the debugger.

2. **Class-by-Class Analysis:**  I'll then go through the major classes and functions, trying to understand their roles and relationships.

    * **`V8CachedObject`:** The name suggests caching of V8 objects. The constructor and `Create` method deal with getting type information and locations. The `GetCachedV8HeapObject` method involves reading memory and expanding compressed pointers, which are common in V8. This seems to be a wrapper around a raw memory location to provide V8-specific context.

    * **`IndexedFieldData`:**  This seems related to handling indexed properties (like array elements). The `GetProperty` method suggests it holds information about such a property.

    * **`V8ObjectKeyEnumerator`:**  The name is self-explanatory – it iterates over the keys (property names) of a V8 object.

    * **`V8LocalDataModel` and `V8ObjectDataModel`:** These are likely related to how data is presented in the debugger. The `ToDisplayString` method in `V8ObjectDataModel` confirms this – it provides a human-readable representation of a V8 object. The `GetKey` and `EnumerateKeys` methods are key for inspecting object properties.

    * **`IndexedFieldParent` and `IndexedFieldIterator`:** These work together to provide iteration over indexed fields (arrays). `GetAt` retrieves an element at a specific index.

    * **`V8LocalValueProperty`, `V8InternalCompilerNodeIdProperty`, `V8InternalCompilerBitsetNameProperty`:**  These appear to be specialized property handlers for specific V8 internal types or concepts. The `GetValue` methods in these classes extract specific information from these internal structures.

    * **`InspectV8ObjectMethod`:** This looks like a debugger command or method that allows a user to inspect a V8 object given its memory address (the "tagged value").

3. **Identifying Key Functionality:** Based on the class analysis, I can list the core functionalities:
    * Caching V8 objects' location and type information.
    * Reading V8 object data from memory, handling compression.
    * Enumerating and retrieving object properties (keys and values).
    * Handling indexed properties (arrays).
    * Providing display strings for V8 objects.
    * Inspecting `v8::Local` handles.
    * Inspecting internal compiler structures (Node IDs, Bitset names).
    * Providing a way to inspect a V8 object given its address.

4. **Checking for Torque:** The prompt specifically asks about Torque. I search the file for the `.tq` extension or any mentions of Torque-specific keywords. I don't find any. This confirms it's not a Torque file.

5. **JavaScript Relevance and Examples:** The code clearly interacts with V8's internal representation of JavaScript objects. I need to provide JavaScript examples that correspond to the C++ code's actions. This involves:
    * Accessing object properties using `object.property` or `object['property']`.
    * Iterating over object properties using `for...in` or `Object.keys()`.
    * Accessing array elements using `array[index]`.
    * Understanding how V8 might represent these concepts internally (hence the mention of "tagged pointers" and "compression").

6. **Code Logic Reasoning (Input/Output):**  The `InspectV8ObjectMethod::Call` function is a good candidate for this. I can create a hypothetical scenario:  The user provides a memory address representing a JavaScript object and optionally its type. The output would be a representation of that object's properties and values as shown in the WinDbg debugger.

7. **Common Programming Errors:** I need to connect the code's functionality to potential errors JavaScript developers might make. This involves thinking about:
    * Trying to access properties that don't exist (leading to `undefined`).
    * Incorrectly accessing array elements (out-of-bounds).
    * Misunderstanding the internal representation of JavaScript values (which this tool helps with).

8. **Refinement and Structuring:** Finally, I organize the information into the requested format, ensuring clarity and accuracy. I use clear headings and bullet points. I double-check the code snippets and explanations to ensure they are correct and easy to understand. I pay attention to the specific requirements of the prompt (e.g., using JavaScript for examples).

Essentially, the process involves: understanding the domain (V8 debugging), dissecting the code into its components, inferring the purpose of each component, connecting the low-level C++ with high-level JavaScript concepts, and then presenting the findings in a structured and informative way.
看起来你提供的是一个 C++ 源代码文件 `object-inspection.cc`，它是 V8 引擎的调试工具 `v8windbg` 的一部分。  根据你的描述，我们来分析一下它的功能：

**主要功能：**

这个文件的主要功能是 **在 WinDbg 调试器中提供 V8 堆对象的检查和展示能力**。  它允许开发者在调试 V8 时，查看 V8 对象的内部结构、属性和值。

**具体功能点：**

1. **`V8CachedObject` 类:**
   -  缓存 V8 堆对象的元数据，例如对象在内存中的位置 (`location_`)、未压缩的类型名称 (`uncompressed_type_name_`) 和关联的调试上下文 (`context_`)。
   -  提供了创建 `V8CachedObject` 实例的方法 (`Create`)，这个方法会从 `IModelObject` 中提取对象的地址、上下文和类型信息。
   -  延迟加载真正的 `V8HeapObject` 数据 (`GetCachedV8HeapObject`)，只有在需要时才去读取内存，并处理压缩指针的情况。

2. **`TryUnwrapTaggedMemberType` 函数:**
   -  尝试解包 `v8::internal::TaggedMember<T>` 类型的模板参数 `T`。这在处理 V8 的标记指针时非常有用，因为它允许我们获取实际指向的类型。

3. **`IndexedFieldData` 类:**
   -  用于存储索引字段（例如数组元素）的属性信息。

4. **`V8ObjectKeyEnumerator` 类:**
   -  实现了 `IKeyEnumerator` 接口，用于枚举 V8 对象的属性键。它通过访问 `V8HeapObject` 的 `properties` 成员来实现。

5. **`V8LocalDataModel` 和 `V8ObjectDataModel` 类:**
   -  实现了调试器数据模型的接口 (`IModelObject`)，允许 WinDbg 理解和展示 V8 对象。
   -  `V8ObjectDataModel::ToDisplayString` 方法负责生成 V8 对象的友好的字符串表示，通常使用 `V8HeapObject` 的 `friendly_name`。
   -  `V8ObjectDataModel::GetKey` 方法允许根据键名获取 V8 对象的属性值。
   -  `V8ObjectDataModel::EnumerateKeys` 方法返回一个 `V8ObjectKeyEnumerator` 实例，用于遍历对象的键。

6. **辅助函数 (匿名命名空间):**
   -  `CreateSyntheticObjectWithParentAndDataContext`: 创建一个合成的调试器对象，并关联父模型和数据上下文。
   -  `CreateSyntheticObjectForV8Object`: 为 `V8CachedObject` 创建一个合成的调试器对象。
   -  `GetModelForBasicField`:  为基本类型的字段（非结构体或数组）创建调试器模型对象。它会处理 `TaggedMember` 类型。
   -  `GetModelForBitField`: 为位域创建调试器模型对象，需要处理位移和读取。
   -  `GetModelForStruct`: 为结构体创建调试器模型对象，递归处理结构体中的字段。
   -  `GetModelForNativeArray`: 为已知类型的原生数组创建调试器模型对象。
   -  `GetModelForCustomArray`: 为自定义数组（例如存储结构体或压缩值的数组）创建调试器模型对象。
   -  `GetModelForCustomArrayElement`: 获取自定义数组中指定索引的元素。
   -  `GetModelForProperty`:  根据 `Property` 结构的信息，选择合适的 `GetModelFor...` 函数来创建调试器模型对象。

7. **`IndexedFieldParent` 和 `IndexedFieldIterator` 类:**
   -  实现了对索引字段的访问和迭代。`IndexedFieldParent::GetAt` 用于获取指定索引的元素，`IndexedFieldParent::GetIterator` 用于获取迭代器。

8. **`V8LocalValueProperty` 类:**
   -  处理 `v8::Local<T>` 类型的属性。它会读取 `v8::Local` 指向的地址，并创建相应的调试器对象。

9. **`V8InternalCompilerNodeIdProperty` 和 `V8InternalCompilerBitsetNameProperty` 类:**
   -  用于检查 V8 编译器内部特定结构的属性，例如节点的 ID 和位集名称。

10. **`InspectV8ObjectMethod` 类:**
    -  实现了一个 WinDbg 的自定义命令或方法，允许用户通过提供一个表示 V8 对象的标记值（内存地址）来检查该对象。

**关于 .tq 结尾:**

你说的很对，如果 `object-inspection.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 使用的一种领域特定语言，用于定义 V8 的内置函数和类型。 然而，这个文件是 `.cc` 结尾，所以它是 **C++ 源代码**。

**与 JavaScript 的关系及示例:**

这个 C++ 代码的功能是服务于 V8 引擎的调试，因此它直接关联着 JavaScript 对象的内部表示。当你在 JavaScript 中创建对象和操作属性时，V8 引擎会在内存中创建相应的 C++ 对象。 `object-inspection.cc` 提供的功能就是让你在 WinDbg 中查看这些底层的 C++ 对象。

**JavaScript 示例：**

```javascript
let myObject = {
  name: "Alice",
  age: 30,
  city: "New York"
};

let myArray = [1, 2, 3];
```

当你在 WinDbg 中调试 V8，并遇到 `myObject` 这个 JavaScript 对象时，`object-inspection.cc` 中的代码会帮助你：

- 查看 `myObject` 在 V8 堆中的内存地址。
- 查看 `myObject` 的类型（例如，可能是 `v8::internal::JSObject`）。
- 遍历 `myObject` 的属性（`name`, `age`, `city`）。
- 查看每个属性的值（例如，`name` 属性的值会是字符串 "Alice" 在 V8 堆中的表示）。
- 对于 `myArray`，你可以查看其作为 V8 数组对象的内部结构和元素。

**代码逻辑推理 (假设输入与输出):**

假设 WinDbg 调试器停在 V8 代码中的某个位置，并且我们有一个 `IModelObject` 指针 `p_v8_object_instance`，它代表一个 JavaScript 对象：

**假设输入:**

- `p_v8_object_instance` 指向一个代表以下 JavaScript 对象的 V8 内部对象：
  ```javascript
  let person = {
    firstName: "Bob",
    age: 25
  };
  ```

**可能的输出 (通过 `V8ObjectDataModel::EnumerateKeys` 和 `V8ObjectDataModel::GetKey`):**

- 调用 `EnumerateKeys` 可能会返回一个迭代器，该迭代器会产生键 `"firstName"` 和 `"age"`。
- 调用 `GetKey` 并传入键 `"firstName"`，可能会返回一个 `IModelObject`，它表示字符串 "Bob" 在 V8 堆中的表示。
- 调用 `GetKey` 并传入键 `"age"`，可能会返回一个 `IModelObject`，它表示数字 25 在 V8 堆中的表示。
- `ToDisplayString` 可能会生成一个类似 `"{firstName: \"Bob\", age: 25}"` 的字符串。

**用户常见的编程错误及示例:**

这个文件本身是调试工具的代码，它不会直接捕获用户 JavaScript 代码的错误。但是，通过使用这个工具，开发者可以更容易地诊断与 V8 对象结构和属性相关的错误。

**示例：**

1. **访问未定义的属性:**

   ```javascript
   let obj = { name: "Charlie" };
   console.log(obj.city.toUpperCase()); // 运行时错误：Cannot read property 'toUpperCase' of undefined
   ```

   使用 `object-inspection.cc` 提供的功能，开发者可以在 WinDbg 中检查 `obj` 对象，确认它确实没有 `city` 属性，从而理解错误的原因。

2. **类型错误:**

   ```javascript
   let count = "5";
   let result = count + 1; // 结果是字符串 "51"，可能不是期望的数字 6
   ```

   如果 `count` 被当作 V8 内部的字符串对象，调试器可以显示其类型，帮助开发者识别类型不匹配的问题。

3. **闭包问题:**

   ```javascript
   function createClosures() {
     const functions = [];
     for (var i = 0; i < 5; i++) {
       functions.push(function() { console.log(i); });
     }
     return functions;
   }

   const closures = createClosures();
   closures[0](); // 输出 5，而不是期望的 0
   ```

   在调试这种涉及作用域和闭包的问题时，检查闭包内部捕获的变量的值（这些值会存储在 V8 的闭包对象中）可以帮助理解错误。

**总结:**

`v8/tools/v8windbg/src/object-inspection.cc` 是一个关键的 V8 调试工具组件，它通过 WinDbg 提供了深入检查 V8 堆对象的能力。这对于理解 JavaScript 代码在 V8 引擎中的底层表示、诊断性能问题和调试复杂错误至关重要。它不直接处理用户的 JavaScript 错误，而是为开发者提供了一个强大的工具来理解和解决这些错误。

### 提示词
```
这是目录为v8/tools/v8windbg/src/object-inspection.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/tools/v8windbg/src/object-inspection.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/v8windbg/src/object-inspection.h"

#include "src/flags/flags.h"
#include "tools/v8windbg/base/utilities.h"
#include "tools/v8windbg/src/v8-debug-helper-interop.h"
#include "tools/v8windbg/src/v8windbg-extension.h"

V8CachedObject::V8CachedObject(Location location,
                               std::string uncompressed_type_name,
                               WRL::ComPtr<IDebugHostContext> context,
                               bool is_compressed)
    : location_(std::move(location)),
      uncompressed_type_name_(std::move(uncompressed_type_name)),
      context_(std::move(context)),
      is_compressed_(is_compressed) {}

HRESULT V8CachedObject::Create(IModelObject* p_v8_object_instance,
                               IV8CachedObject** result) {
  Location location;
  RETURN_IF_FAIL(p_v8_object_instance->GetLocation(&location));

  WRL::ComPtr<IDebugHostContext> context;
  RETURN_IF_FAIL(p_v8_object_instance->GetContext(&context));

  WRL::ComPtr<IDebugHostType> sp_tagged_type;
  RETURN_IF_FAIL(p_v8_object_instance->GetTypeInfo(&sp_tagged_type));

  // The type is some Tagged<T>, so we need to get the first generic type
  // parameter.
  bool is_generic;
  RETURN_IF_FAIL(sp_tagged_type->IsGeneric(&is_generic));
  if (!is_generic) return E_FAIL;

  WRL::ComPtr<IDebugHostSymbol> sp_generic_arg;
  RETURN_IF_FAIL(sp_tagged_type->GetGenericArgumentAt(0, &sp_generic_arg));

  _bstr_t type_name;
  RETURN_IF_FAIL(sp_generic_arg->GetName(type_name.GetAddress()));

  bool is_compressed = false;
  *result =
      WRL::Make<V8CachedObject>(location, static_cast<const char*>(type_name),
                                context, is_compressed)
          .Detach();
  return S_OK;
}

V8CachedObject::V8CachedObject(V8HeapObject heap_object)
    : heap_object_(std::move(heap_object)), heap_object_initialized_(true) {}

V8CachedObject::~V8CachedObject() = default;

IFACEMETHODIMP V8CachedObject::GetCachedV8HeapObject(
    V8HeapObject** pp_heap_object) noexcept {
  if (!heap_object_initialized_) {
    heap_object_initialized_ = true;
    uint64_t tagged_ptr = 0;
    uint64_t bytes_read;
    HRESULT hr = sp_debug_host_memory->ReadBytes(
        context_.Get(), location_, reinterpret_cast<void*>(&tagged_ptr),
        is_compressed_ ? i::kTaggedSize : sizeof(void*), &bytes_read);
    // S_FALSE can be returned if fewer bytes were read than were requested. We
    // need all of the bytes, so check for S_OK.
    if (hr != S_OK) {
      std::stringstream message;
      message << "Unable to read memory";
      if (location_.IsVirtualAddress()) {
        message << " at 0x" << std::hex << location_.GetOffset();
      }
      heap_object_.friendly_name = ConvertToU16String(message.str());
    } else {
      if (is_compressed_)
        tagged_ptr = ExpandCompressedPointer(static_cast<uint32_t>(tagged_ptr));
      heap_object_ =
          ::GetHeapObject(context_, tagged_ptr, location_.GetOffset(),
                          uncompressed_type_name_.c_str(), is_compressed_);
    }
  }
  *pp_heap_object = &this->heap_object_;
  return S_OK;
}

bool TryUnwrapTaggedMemberType(const std::u16string& type,
                               std::u16string* result) {
  std::u16string prefix = u"v8::internal::TaggedMember<";
  if (type.substr(0, prefix.length()) == prefix && type.back() == u'>') {
    if (result) {
      *result =
          type.substr(prefix.length(), type.length() - prefix.length() - 1);
    }
    return true;
  }
  return false;
}

IndexedFieldData::IndexedFieldData(Property property)
    : property_(std::move(property)) {}

IndexedFieldData::~IndexedFieldData() = default;

IFACEMETHODIMP IndexedFieldData::GetProperty(Property** property) noexcept {
  if (!property) return E_POINTER;
  *property = &this->property_;
  return S_OK;
}

V8ObjectKeyEnumerator::V8ObjectKeyEnumerator(
    WRL::ComPtr<IV8CachedObject>& v8_cached_object)
    : sp_v8_cached_object_{v8_cached_object} {}
V8ObjectKeyEnumerator::~V8ObjectKeyEnumerator() = default;

IFACEMETHODIMP V8ObjectKeyEnumerator::Reset() noexcept {
  index_ = 0;
  return S_OK;
}

IFACEMETHODIMP V8ObjectKeyEnumerator::GetNext(BSTR* key, IModelObject** value,
                                              IKeyStore** metadata) noexcept {
  V8HeapObject* p_v8_heap_object;
  sp_v8_cached_object_->GetCachedV8HeapObject(&p_v8_heap_object);

  if (static_cast<size_t>(index_) >= p_v8_heap_object->properties.size())
    return E_BOUNDS;

  auto* name_ptr = p_v8_heap_object->properties[index_].name.c_str();
  *key = ::SysAllocString(U16ToWChar(name_ptr));
  ++index_;
  return S_OK;
}

IFACEMETHODIMP V8LocalDataModel::InitializeObject(
    IModelObject* model_object,
    IDebugHostTypeSignature* matching_type_signature,
    IDebugHostSymbolEnumerator* wildcard_matches) noexcept {
  return S_OK;
}

IFACEMETHODIMP V8LocalDataModel::GetName(BSTR* model_name) noexcept {
  return E_NOTIMPL;
}

IFACEMETHODIMP V8ObjectDataModel::InitializeObject(
    IModelObject* model_object,
    IDebugHostTypeSignature* matching_type_signature,
    IDebugHostSymbolEnumerator* wildcard_matches) noexcept {
  return S_OK;
}

IFACEMETHODIMP V8ObjectDataModel::GetName(BSTR* model_name) noexcept {
  return E_NOTIMPL;
}

IFACEMETHODIMP V8ObjectDataModel::ToDisplayString(
    IModelObject* context_object, IKeyStore* metadata,
    BSTR* display_string) noexcept {
  WRL::ComPtr<IV8CachedObject> sp_v8_cached_object;
  RETURN_IF_FAIL(GetCachedObject(context_object, &sp_v8_cached_object));
  V8HeapObject* p_v8_heap_object;
  RETURN_IF_FAIL(sp_v8_cached_object->GetCachedV8HeapObject(&p_v8_heap_object));
  *display_string = ::SysAllocString(
      reinterpret_cast<const wchar_t*>(p_v8_heap_object->friendly_name.data()));
  return S_OK;
}

namespace {

// Creates a synthetic object, attaches a parent model, and sets the context
// object for that parent data model. Caller is responsible for ensuring that
// the parent model's Concepts have been initialized correctly and that the
// data model context is of an appropriate type for the parent model.
HRESULT CreateSyntheticObjectWithParentAndDataContext(
    IDebugHostContext* ctx, IModelObject* parent_model, IUnknown* data_context,
    IModelObject** result) {
  WRL::ComPtr<IModelObject> value;
  RETURN_IF_FAIL(sp_data_model_manager->CreateSyntheticObject(ctx, &value));
  RETURN_IF_FAIL(
      value->AddParentModel(parent_model, nullptr, true /*override*/));
  RETURN_IF_FAIL(value->SetContextForDataModel(parent_model, data_context));
  *result = value.Detach();
  return S_OK;
}

// Creates an IModelObject for a V8 object whose value is represented by the
// data in cached_object. This is an alternative to  CreateTypedObject for
// particularly complex cases (compressed values and those that don't exist
// anywhere in memory).
HRESULT CreateSyntheticObjectForV8Object(IDebugHostContext* ctx,
                                         V8CachedObject* cached_object,
                                         IModelObject** result) {
  // Explicitly add the parent model and data context. On a plain typed object,
  // the parent model would be attached automatically because we registered for
  // a matching type signature, and the data context would be set during
  // V8ObjectDataModel::GetCachedObject.
  return CreateSyntheticObjectWithParentAndDataContext(
      ctx, Extension::Current()->GetObjectDataModel(), cached_object, result);
}

// Creates an IModelObject to represent a field that is not a struct or array.
HRESULT GetModelForBasicField(const uint64_t address,
                              const std::u16string& type_name,
                              WRL::ComPtr<IDebugHostContext>& sp_ctx,
                              IModelObject** result) {
  // We can't currently look up TaggedMember types for two reasons:
  // 1. We need to insert the default template parameter; TaggedMember<T> is
  //    actually TaggedMember<T, V8HeapCompressionScheme>.
  // 2. No TaggedMember classes are currently instantiated in the V8 module,
  //    and the debugger won't invent new template types.
  // Thus, we must check using string manipulation whether this field is a
  // TaggedMember, and create a synthetic object for the field.
  std::u16string unwrapped_type_name;
  if (!TryUnwrapTaggedMemberType(type_name, &unwrapped_type_name)) {
    WRL::ComPtr<IDebugHostType> type =
        Extension::Current()->GetTypeFromV8Module(sp_ctx, type_name.c_str());
    if (type == nullptr) return E_FAIL;
    return sp_data_model_manager->CreateTypedObject(
        sp_ctx.Get(), Location{address}, type.Get(), result);
  }

  // For tagged fields, we need to do something a little more
  // complicated. We could just use CreateTypedObject with the type
  // v8::internal::TaggedValue, but then we'd sacrifice any other data
  // that we've learned about the field's specific type. So instead we
  // create a synthetic object.
  WRL::ComPtr<V8CachedObject> cached_object = WRL::Make<V8CachedObject>(
      Location(address), ConvertFromU16String(unwrapped_type_name), sp_ctx,
      COMPRESS_POINTERS_BOOL);
  return CreateSyntheticObjectForV8Object(sp_ctx.Get(), cached_object.Get(),
                                          result);
}

// Creates an IModelObject representing the value of a bitfield.
HRESULT GetModelForBitField(uint64_t address, const uint8_t num_bits,
                            uint8_t shift_bits, const std::u16string& type_name,
                            WRL::ComPtr<IDebugHostContext>& sp_ctx,
                            IModelObject** result) {
  // Look up the type by name.
  WRL::ComPtr<IDebugHostType> type =
      Extension::Current()->GetTypeFromV8Module(sp_ctx, type_name.c_str());
  if (type == nullptr) return E_FAIL;

  // Figure out exactly which bytes contain the bitfield's data. This depends on
  // platform byte order (little-endian for Windows).
  constexpr int kBitsPerByte = 8;
  uint8_t shift_bytes = shift_bits / kBitsPerByte;
  address += shift_bytes;
  shift_bits -= shift_bytes * kBitsPerByte;
  size_t bits_to_read = shift_bits + num_bits;
  size_t bytes_to_read = (bits_to_read + kBitsPerByte - 1) / kBitsPerByte;

  uintptr_t value = 0;

  // V8 guarantees that bitfield structs are no bigger than a single pointer.
  if (bytes_to_read > sizeof(value)) {
    std::stringstream message;
    message << "Fatal v8windbg error: found bitfield struct of "
            << bytes_to_read << "bytes, which exceeds the supported size of "
            << sizeof(value);
    return CreateString(ConvertToU16String(message.str()), result);
  }

  uint64_t bytes_read;
  HRESULT hr = sp_debug_host_memory->ReadBytes(sp_ctx.Get(), address,
                                               reinterpret_cast<void*>(&value),
                                               bytes_to_read, &bytes_read);

  // S_FALSE can be returned if fewer bytes were read than were requested. We
  // need all of the bytes, so check for S_OK.
  if (hr != S_OK) {
    std::stringstream message;
    message << "Unable to read memory at 0x" << std::hex << address;
    return CreateString(ConvertToU16String(message.str()), result);
  }

  // Decode the bitfield.
  value = (value >> shift_bits) & ((1 << num_bits) - 1);

  return CreateTypedIntrinsic(value, type.Get(), result);
}

// Creates an IModelObject to represent the packed fields in a Torque struct.
// Note that Torque structs are not C++ structs and do not have any type
// definitions in the V8 symbols.
HRESULT GetModelForStruct(const uint64_t address,
                          const std::vector<StructField>& fields,
                          WRL::ComPtr<IDebugHostContext>& sp_ctx,
                          IModelObject** result) {
  WRL::ComPtr<IModelObject> sp_value;
  RETURN_IF_FAIL(
      sp_data_model_manager->CreateSyntheticObject(sp_ctx.Get(), &sp_value));

  // There's no need for any fancy Concepts here; just add key-value pairs for
  // each field.
  for (const StructField& field : fields) {
    WRL::ComPtr<IModelObject> field_model;
    if (field.num_bits == 0) {
      if (FAILED(GetModelForBasicField(address + field.offset, field.type_name,
                                       sp_ctx, &field_model))) {
        continue;
      }
    } else {
      if (FAILED(GetModelForBitField(address + field.offset, field.num_bits,
                                     field.shift_bits, field.type_name, sp_ctx,
                                     &field_model))) {
        continue;
      }
    }
    RETURN_IF_FAIL(
        sp_value->SetKey(reinterpret_cast<const wchar_t*>(field.name.c_str()),
                         field_model.Get(), nullptr));
  }

  *result = sp_value.Detach();
  return S_OK;
}

// Creates an IModelObject representing an array of some type that we expect to
// be defined in the V8 symbols.
HRESULT GetModelForNativeArray(const uint64_t address,
                               const std::u16string& type_name, size_t count,
                               WRL::ComPtr<IDebugHostContext>& sp_ctx,
                               IModelObject** result) {
  WRL::ComPtr<IDebugHostType> type =
      Extension::Current()->GetTypeFromV8Module(sp_ctx, type_name.c_str());
  if (type == nullptr) return E_FAIL;

  ULONG64 object_size{};
  RETURN_IF_FAIL(type->GetSize(&object_size));

  ArrayDimension dimensions[] = {
      {/*start=*/0, /*length=*/count, /*stride=*/object_size}};
  WRL::ComPtr<IDebugHostType> array_type;
  RETURN_IF_FAIL(
      type->CreateArrayOf(/*dimensions=*/1, dimensions, &array_type));

  return sp_data_model_manager->CreateTypedObject(
      sp_ctx.Get(), Location{address}, array_type.Get(), result);
}

// Creates an IModelObject that represents an array of structs or compressed
// tagged values.
HRESULT GetModelForCustomArray(const Property& prop,
                               WRL::ComPtr<IDebugHostContext>& sp_ctx,
                               IModelObject** result) {
  // Create the context which should be provided to the indexing and iterating
  // functionality provided by the parent model. This is instance-specific data,
  // whereas the parent model object could be shared among many custom arrays.
  WRL::ComPtr<IndexedFieldData> context_data =
      WRL::Make<IndexedFieldData>(prop);

  return CreateSyntheticObjectWithParentAndDataContext(
      sp_ctx.Get(), Extension::Current()->GetIndexedFieldDataModel(),
      context_data.Get(), result);
}


// Creates an IModelObject representing the data in an array at the given index.
// context_object is expected to be an object of the form created by
// GetModelForCustomArray, meaning its context for the IndexedFieldParent data
// model is an IIndexedFieldData containing the description of the array.
HRESULT GetModelForCustomArrayElement(IModelObject* context_object,
                                      size_t index, IModelObject** object) {
  // Open a few layers of wrapper objects to get to the Property object that
  // describes the array.
  WRL::ComPtr<IUnknown> data_model_context;
  RETURN_IF_FAIL(context_object->GetContextForDataModel(
      Extension::Current()->GetIndexedFieldDataModel(), &data_model_context));
  WRL::ComPtr<IIndexedFieldData> indexed_field_data;
  RETURN_IF_FAIL(data_model_context.As(&indexed_field_data));
  Property* prop;
  RETURN_IF_FAIL(indexed_field_data->GetProperty(&prop));

  if (index >= prop->length) {
    return E_BOUNDS;
  }

  WRL::ComPtr<IDebugHostContext> sp_ctx;
  RETURN_IF_FAIL(context_object->GetContext(&sp_ctx));

  ULONG64 address = prop->addr_value + index * prop->item_size;

  switch (prop->type) {
    case PropertyType::kArray:
      return GetModelForBasicField(address, prop->type_name, sp_ctx, object);
    case PropertyType::kStructArray:
      return GetModelForStruct(address, prop->fields, sp_ctx, object);
    default:
      return E_FAIL;  // Only array properties should be possible here.
  }
}

}  // namespace

IFACEMETHODIMP IndexedFieldParent::InitializeObject(
    IModelObject* model_object,
    IDebugHostTypeSignature* matching_type_signature,
    IDebugHostSymbolEnumerator* wildcard_matches) noexcept {
  return S_OK;
}

IFACEMETHODIMP IndexedFieldParent::GetName(BSTR* model_name) noexcept {
  return E_NOTIMPL;
}

IFACEMETHODIMP IndexedFieldParent::GetDimensionality(
    IModelObject* context_object, ULONG64* dimensionality) noexcept {
  *dimensionality = 1;
  return S_OK;
}

IFACEMETHODIMP IndexedFieldParent::GetAt(IModelObject* context_object,
                                         ULONG64 indexer_count,
                                         IModelObject** indexers,
                                         IModelObject** object,
                                         IKeyStore** metadata) noexcept {
  if (indexer_count != 1) return E_INVALIDARG;
  if (metadata != nullptr) *metadata = nullptr;

  ULONG64 index;
  RETURN_IF_FAIL(UnboxULong64(indexers[0], &index, /*convert=*/true));

  return GetModelForCustomArrayElement(context_object, index, object);
}

IFACEMETHODIMP IndexedFieldParent::SetAt(IModelObject* context_object,
                                         ULONG64 indexer_count,
                                         IModelObject** indexers,
                                         IModelObject* value) noexcept {
  return E_NOTIMPL;
}

IFACEMETHODIMP IndexedFieldParent::GetDefaultIndexDimensionality(
    IModelObject* context_object, ULONG64* dimensionality) noexcept {
  *dimensionality = 1;
  return S_OK;
}

IFACEMETHODIMP IndexedFieldParent::GetIterator(
    IModelObject* context_object, IModelIterator** iterator) noexcept {
  auto indexed_field_iterator{WRL::Make<IndexedFieldIterator>(context_object)};
  *iterator = indexed_field_iterator.Detach();
  return S_OK;
}

IndexedFieldIterator::IndexedFieldIterator(IModelObject* context_object)
    : context_object_(context_object) {}
IndexedFieldIterator::~IndexedFieldIterator() = default;

IFACEMETHODIMP IndexedFieldIterator::Reset() noexcept {
  next_ = 0;
  return S_OK;
}

IFACEMETHODIMP IndexedFieldIterator::GetNext(IModelObject** object,
                                             ULONG64 dimensions,
                                             IModelObject** indexers,
                                             IKeyStore** metadata) noexcept {
  if (dimensions > 1) return E_INVALIDARG;

  WRL::ComPtr<IModelObject> sp_index, sp_value;
  RETURN_IF_FAIL(
      GetModelForCustomArrayElement(context_object_.Get(), next_, &sp_value));
  RETURN_IF_FAIL(CreateULong64(next_, &sp_index));

  // Everything that could fail (including the bounds check) has succeeded, so
  // increment the index.
  ++next_;

  // Write results (none of these steps can fail, which is important because we
  // transfer ownership of two separate objects).
  if (dimensions == 1) {
    indexers[0] = sp_index.Detach();
  }
  *object = sp_value.Detach();
  if (metadata != nullptr) *metadata = nullptr;
  return S_OK;
}

IFACEMETHODIMP V8ObjectDataModel::GetKey(IModelObject* context_object,
                                         PCWSTR key, IModelObject** key_value,
                                         IKeyStore** metadata,
                                         bool* has_key) noexcept {
  if (metadata != nullptr) *metadata = nullptr;

  WRL::ComPtr<IV8CachedObject> sp_v8_cached_object;
  RETURN_IF_FAIL(GetCachedObject(context_object, &sp_v8_cached_object));
  V8HeapObject* p_v8_heap_object;
  RETURN_IF_FAIL(sp_v8_cached_object->GetCachedV8HeapObject(&p_v8_heap_object));

  *has_key = false;
  for (const auto& prop : p_v8_heap_object->properties) {
    const char16_t* p_key = reinterpret_cast<const char16_t*>(key);
    if (prop.name.compare(p_key) == 0) {
      *has_key = true;
      if (key_value != nullptr) {
        WRL::ComPtr<IDebugHostContext> sp_ctx;
        RETURN_IF_FAIL(context_object->GetContext(&sp_ctx));
        RETURN_IF_FAIL(GetModelForProperty(prop, sp_ctx, key_value));
      }
      return S_OK;
    }
  }

  return S_OK;
}

IFACEMETHODIMP V8ObjectDataModel::SetKey(IModelObject* context_object,
                                         PCWSTR key, IModelObject* key_value,
                                         IKeyStore* metadata) noexcept {
  return E_NOTIMPL;
}

IFACEMETHODIMP V8ObjectDataModel::EnumerateKeys(
    IModelObject* context_object, IKeyEnumerator** pp_enumerator) noexcept {
  WRL::ComPtr<IV8CachedObject> sp_v8_cached_object;
  RETURN_IF_FAIL(GetCachedObject(context_object, &sp_v8_cached_object));

  auto enumerator{WRL::Make<V8ObjectKeyEnumerator>(sp_v8_cached_object)};
  *pp_enumerator = enumerator.Detach();
  return S_OK;
}

IFACEMETHODIMP V8LocalValueProperty::GetValue(
    PCWSTR pwsz_key, IModelObject* p_v8_local_instance,
    IModelObject** pp_value) noexcept {
  // Get the parametric type within v8::Local<*>
  // Set value to a pointer to an instance of this type.

  WRL::ComPtr<IDebugHostType> sp_type;
  RETURN_IF_FAIL(p_v8_local_instance->GetTypeInfo(&sp_type));

  bool is_generic;
  RETURN_IF_FAIL(sp_type->IsGeneric(&is_generic));
  if (!is_generic) return E_FAIL;

  WRL::ComPtr<IDebugHostSymbol> sp_generic_arg;
  RETURN_IF_FAIL(sp_type->GetGenericArgumentAt(0, &sp_generic_arg));

  _bstr_t generic_name;
  RETURN_IF_FAIL(sp_generic_arg->GetName(generic_name.GetAddress()));

  WRL::ComPtr<IDebugHostContext> sp_ctx;
  RETURN_IF_FAIL(p_v8_local_instance->GetContext(&sp_ctx));

  Location loc;
  RETURN_IF_FAIL(p_v8_local_instance->GetLocation(&loc));

  // Read the pointer at the Object location
  ULONG64 obj_address;
  RETURN_IF_FAIL(
      sp_debug_host_memory->ReadPointers(sp_ctx.Get(), loc, 1, &obj_address));

  // If the val_ is a nullptr, then there is no value in the Local.
  if (obj_address == 0) {
    RETURN_IF_FAIL(CreateString(std::u16string{u"<empty>"}, pp_value));
  } else {
    // Get the corresponding Tagged<T> type for the generic_name found above.
    std::string narrow_tagged_name = std::string("v8::internal::Tagged<") +
                                     static_cast<const char*>(generic_name) +
                                     ">";
    std::u16string tagged_type_name = ConvertToU16String(narrow_tagged_name);
    WRL::ComPtr<IDebugHostType> tagged_type =
        Extension::Current()->GetTypeFromV8Module(sp_ctx,
                                                  tagged_type_name.c_str());
    if (tagged_type == nullptr) {
      // If we couldn't find the specific tagged type, try to find
      // Tagged<Object> instead.
      tagged_type = Extension::Current()->GetV8TaggedObjectType(sp_ctx);
    }

    // Create the result.
    RETURN_IF_FAIL(sp_data_model_manager->CreateTypedObject(
        sp_ctx.Get(), obj_address, tagged_type.Get(), pp_value));
  }

  return S_OK;
}

IFACEMETHODIMP V8LocalValueProperty::SetValue(
    PCWSTR /*pwsz_key*/, IModelObject* /*p_process_instance*/,
    IModelObject* /*p_value*/) noexcept {
  return E_NOTIMPL;
}

IFACEMETHODIMP V8InternalCompilerNodeIdProperty::GetValue(
    PCWSTR pwsz_key, IModelObject* p_v8_compiler_node_instance,
    IModelObject** pp_value) noexcept {
  WRL::ComPtr<IModelObject> sp_bit_field;
  RETURN_IF_FAIL(p_v8_compiler_node_instance->GetRawValue(
      SymbolKind::SymbolField, L"bit_field_", RawSearchNone, &sp_bit_field));

  uint64_t bit_field_value;
  RETURN_IF_FAIL(
      UnboxULong64(sp_bit_field.Get(), &bit_field_value, true /*convert*/));

  WRL::ComPtr<IDebugHostContext> sp_host_context;
  RETURN_IF_FAIL(p_v8_compiler_node_instance->GetContext(&sp_host_context));

  WRL::ComPtr<IDebugHostType> sp_id_field_type;
  RETURN_IF_FAIL(Extension::Current()
                     ->GetV8Module(sp_host_context)
                     ->FindTypeByName(L"v8::internal::compiler::Node::IdField",
                                      &sp_id_field_type));

  // Get 2nd template parameter as 24 in class.
  // v8::base::BitField<v8::internal::compiler::NodeId, 0, 24>.
  bool is_generic;
  RETURN_IF_FAIL(sp_id_field_type->IsGeneric(&is_generic));
  if (!is_generic) return E_FAIL;

  WRL::ComPtr<IDebugHostSymbol> sp_k_size_arg;
  RETURN_IF_FAIL(sp_id_field_type->GetGenericArgumentAt(2, &sp_k_size_arg));

  WRL::ComPtr<IDebugHostConstant> sp_k_size_constant;
  RETURN_IF_FAIL(sp_k_size_arg.As(&sp_k_size_constant));

  int k_size;
  RETURN_IF_FAIL(GetInt32(sp_k_size_constant.Get(), &k_size));

  // Compute node_id.
  uint32_t node_id = bit_field_value & (0xFFFFFFFF >> k_size);
  RETURN_IF_FAIL(CreateUInt32(node_id, pp_value));

  return S_OK;
}

IFACEMETHODIMP V8InternalCompilerNodeIdProperty::SetValue(
    PCWSTR /*pwsz_key*/, IModelObject* /*p_process_instance*/,
    IModelObject* /*p_value*/) noexcept {
  return E_NOTIMPL;
}

IFACEMETHODIMP V8InternalCompilerBitsetNameProperty::GetValue(
    PCWSTR pwsz_key, IModelObject* p_v8_compiler_type_instance,
    IModelObject** pp_value) noexcept {
  WRL::ComPtr<IModelObject> sp_payload;
  RETURN_IF_FAIL(p_v8_compiler_type_instance->GetRawValue(
      SymbolKind::SymbolField, L"payload_", RawSearchNone, &sp_payload));

  uint64_t payload_value;
  RETURN_IF_FAIL(
      UnboxULong64(sp_payload.Get(), &payload_value, true /*convert*/));

  const char* bitset_name = ::BitsetName(payload_value);
  if (!bitset_name) return E_FAIL;
  std::string name(bitset_name);
  RETURN_IF_FAIL(CreateString(ConvertToU16String(name), pp_value));

  return S_OK;
}

IFACEMETHODIMP V8InternalCompilerBitsetNameProperty::SetValue(
    PCWSTR /*pwsz_key*/, IModelObject* /*p_process_instance*/,
    IModelObject* /*p_value*/) noexcept {
  return E_NOTIMPL;
}

constexpr wchar_t usage[] =
    LR"(Invalid arguments.
First argument should be a uint64 representing the tagged value to investigate.
Second argument is optional, and may be a fully-qualified type name such as
v8::internal::String.)";

IFACEMETHODIMP InspectV8ObjectMethod::Call(IModelObject* p_context_object,
                                           ULONG64 arg_count,
                                           _In_reads_(arg_count)
                                               IModelObject** pp_arguments,
                                           IModelObject** pp_result,
                                           IKeyStore** pp_metadata) noexcept {
  // Read the arguments.
  ULONG64 tagged_value;
  _bstr_t type_name;
  if (arg_count < 1 ||
      FAILED(UnboxULong64(pp_arguments[0], &tagged_value, /*convert=*/true)) ||
      (arg_count >= 2 &&
       FAILED(UnboxString(pp_arguments[1], type_name.GetAddress())))) {
    sp_data_model_manager->CreateErrorObject(E_INVALIDARG, usage, pp_result);
    return E_INVALIDARG;
  }

  WRL::ComPtr<IDebugHostContext> sp_ctx;
  RETURN_IF_FAIL(sp_debug_host->GetCurrentContext(&sp_ctx));

  // We can't use CreateTypedObject for a value which may not actually reside
  // anywhere in memory, so create a synthetic object.
  WRL::ComPtr<V8CachedObject> cached_object =
      WRL::Make<V8CachedObject>(::GetHeapObject(
          sp_ctx, tagged_value, 0, static_cast<const char*>(type_name),
          /*is_compressed=*/false));
  return CreateSyntheticObjectForV8Object(sp_ctx.Get(), cached_object.Get(),
                                          pp_result);
}

// Creates an IModelObject representing the data in the given property.
HRESULT GetModelForProperty(const Property& prop,
                            WRL::ComPtr<IDebugHostContext>& sp_ctx,
                            IModelObject** result) {
  switch (prop.type) {
    case PropertyType::kPointer:
      return GetModelForBasicField(prop.addr_value, prop.type_name, sp_ctx,
                                   result);
    case PropertyType::kStruct:
      return GetModelForStruct(prop.addr_value, prop.fields, sp_ctx, result);
    case PropertyType::kArray:
    case PropertyType::kStructArray:
      // We can't currently look up types for TaggedMember and must use custom
      // arrays; see comments in GetModelForBasicField for more details.
      if (prop.type == PropertyType::kArray &&
          !TryUnwrapTaggedMemberType(prop.type_name, nullptr)) {
        // An array of things that are not structs or compressed tagged values
        // is most cleanly represented by a native array.
        return GetModelForNativeArray(prop.addr_value, prop.type_name,
                                      prop.length, sp_ctx, result);
      }
      // Otherwise, we must construct a custom iterable object.
      return GetModelForCustomArray(prop, sp_ctx, result);
    default:
      return E_FAIL;
  }
}
```