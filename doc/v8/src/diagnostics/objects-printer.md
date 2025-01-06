Response: The user wants me to summarize the functionality of the provided C++ code snippet, which is the first part of a larger file.

Based on the included headers and the function names, I can identify the core purpose of this code: it's a debugging utility within the V8 JavaScript engine, specifically for printing the internal structure and values of various V8 objects.

Here's a breakdown of the key functionalities:

1. **Generic Object Printing:**  Provides functions `Print(Tagged<Object> obj)` to output the representation of any V8 object to a stream. It handles `Smi` (small integers) separately and delegates to `HeapObjectPrint` for other objects.
2. **Callback Information Printing:**  Includes specialized functions to print the details of `FunctionCallbackInfo` and `PropertyCallbackInfo`, which are crucial for understanding how native C++ functions interact with JavaScript.
3. **Heap Object Header Printing:** Offers functions to print the header information of `HeapObject` instances, including their address, type, and map.
4. **Dictionary Printing:** Contains functions to print the contents of various dictionary-like data structures used in V8, such as `ObjectHashTable`, `NameDictionary`, `NumberDictionary`, etc. This includes iterating through entries and displaying keys and values.
5. **JSObject Printing:** Provides functions to print details about `JSObject` instances, including their properties, elements, prototype, and embedder data. It handles both fast and dictionary property modes.
6. **Array Printing:** Functions to print the elements of different array types like `FixedArray`, `FixedDoubleArray`, and typed arrays. It also handles sparse arrays and the "hole" value.
7. **Context Printing:**  Functions to print the structure and contents of different types of JavaScript contexts (`Context`, `NativeContext`).
8. **Code Object Printing:** While not explicitly detailed in this snippet, the inclusion of `<code-kind.h>` and `<objects/code-kind.h>` hints at the capability to print information related to compiled JavaScript code.
9. **String Printing:** Includes a function to print the content of `String` objects.
10. **Other V8 Specific Object Printing:**  The code has specialized print functions for numerous other V8 internal object types, such as `Symbol`, `DescriptorArray`, `FeedbackVector`, `JSFunction`, `JSPromise`, `JSRegExp`, and many more.

The strong connection to JavaScript lies in the fact that this code is designed to inspect the runtime representation of JavaScript objects within the V8 engine. The various `JS*` prefixed types (e.g., `JSObject`, `JSArray`, `JSFunction`) directly correspond to JavaScript language constructs.
这个C++代码文件（`objects-printer.cc`）的主要功能是为V8 JavaScript引擎提供一个**调试和查看内部对象结构的工具**。

具体来说，这个文件的代码定义了一系列用于将V8引擎内部的各种对象（例如：Smi，HeapObject，JSObject，Array，Function，Context等）的信息**格式化打印**到输出流的函数。这些函数能够展示对象的类型、地址、内部字段的值，以及与其他对象的关联关系。

**概括其功能如下：**

1. **通用对象打印:**  提供一个通用的 `Print` 函数，可以根据对象的类型调用相应的打印函数，将任何V8对象的信息输出到指定的输出流（例如，控制台或调试器）。
2. **基本类型打印:** 针对像 `Smi` 这样的基本类型，提供简单的格式化输出。
3. **堆对象打印:**  为各种 `HeapObject` 的子类（例如 `JSObject`, `Array`, `String`, `Function` 等）提供了特定的 `Print` 函数。这些函数会打印出该对象特有的内部结构和数据。
4. **回调信息打印:** 提供了打印 `FunctionCallbackInfo` 和 `PropertyCallbackInfo` 的函数，这对于理解Native C++代码如何与JavaScript交互非常有用。
5. **字典打印:**  提供了打印各种字典类型的数据结构（例如 `ObjectHashTable`, `NameDictionary`）的函数，用于查看对象的属性存储情况。
6. **数组打印:**  提供了打印各种数组类型（例如 `FixedArray`, `FixedDoubleArray`, Typed Arrays）的函数，可以查看数组的元素。
7. **上下文打印:**  提供了打印不同类型的 JavaScript 执行上下文 (`Context`, `NativeContext`) 的函数。
8. **其他V8内部对象打印:**  为许多其他的 V8 内部对象类型提供了打印功能，例如 `Symbol`, `FeedbackVector`, `Code` 等。

**与JavaScript功能的关联以及JavaScript示例:**

这个C++文件的功能直接关联到JavaScript的功能，因为它允许开发者和V8引擎的维护者**观察和理解 JavaScript 对象在 V8 引擎内部的表示方式和状态**。

假设我们在JavaScript中创建了一个简单的对象和一个函数：

```javascript
const myObject = {
  name: "example",
  value: 123
};

function myFunction(arg) {
  console.log(arg);
}
```

在V8引擎的调试模式下，或者使用特定的V8 API，我们可以利用 `objects-printer.cc` 中提供的功能来查看 `myObject` 和 `myFunction` 在内存中的具体结构。

例如，`JSObjectPrint` 函数会被用来打印 `myObject` 的信息，展示其属性（"name" 和 "value"）是如何存储的，以及它们对应的值。 `JSFunctionPrint` 函数会打印 `myFunction` 的信息，包括它的代码地址、闭包信息等。

虽然我们不能直接从JavaScript代码中调用这些C++打印函数，但这些函数是V8引擎内部调试和诊断的关键组成部分。  当开发者在V8引擎的源代码中进行调试或者需要深入理解V8的内部机制时，这些打印函数非常有用。

**总结来说，`objects-printer.cc` 的功能是提供一个详细查看 V8 引擎内部对象状态的 C++ 工具，这对于理解 JavaScript 代码在 V8 中的运行时表示至关重要。**

Prompt: 
```
这是目录为v8/src/diagnostics/objects-printer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iomanip>
#include <memory>
#include <optional>

#include "src/api/api-arguments.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/diagnostics/disasm.h"
#include "src/diagnostics/disassembler.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate-utils-inl.h"
#include "src/heap/heap-inl.h"  // For InOldSpace.
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-write-barrier-inl.h"  // For GetIsolateFromWritableObj.
#include "src/heap/marking-inl.h"
#include "src/ic/handler-configuration-inl.h"
#include "src/init/bootstrapper.h"
#include "src/interpreter/bytecodes.h"
#include "src/objects/all-objects-inl.h"
#include "src/objects/code-kind.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-function-inl.h"
#include "src/objects/js-objects.h"
#include "src/regexp/regexp.h"
#include "src/sandbox/isolate.h"
#include "src/sandbox/js-dispatch-table.h"
#include "src/snapshot/embedded/embedded-data.h"
#include "src/strings/string-stream.h"
#include "src/utils/ostreams.h"
#include "third_party/fp16/src/include/fp16.h"
#include "v8-internal.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/debug/debug-wasm-objects-inl.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-objects-inl.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8::internal {

namespace {
constexpr char kUnavailableString[] = "unavailable";
}  // namespace

#ifdef OBJECT_PRINT

void Print(Tagged<Object> obj) {
  // Output into debugger's command window if a debugger is attached.
  DbgStdoutStream dbg_os;
  Print(obj, dbg_os);
  dbg_os << std::flush;

  StdoutStream os;
  Print(obj, os);
  os << std::flush;
}

void Print(Tagged<Object> obj, std::ostream& os) {
  if (IsSmi(obj)) {
    os << "Smi: " << std::hex << "0x" << Smi::ToInt(obj);
    os << std::dec << " (" << Smi::ToInt(obj) << ")\n";
  } else {
    Cast<HeapObject>(obj)->HeapObjectPrint(os);
  }
}

namespace {

#define AS_PTR(x) reinterpret_cast<void*>(x)
#define AS_OBJ(x) Brief(Tagged<Object>(x))

void PrintFunctionCallbackInfo(Address* implicit_args, Address* js_args,
                               Address length, std::ostream& os) {
  using FCA = FunctionCallbackArguments;

  static_assert(FCA::kArgsLength == 6);
  os << "FunctionCallbackInfo: "  //
     << "\n - isolate: " << AS_PTR(implicit_args[FCA::kIsolateIndex])
     << "\n - return_value: " << AS_OBJ(implicit_args[FCA::kReturnValueIndex])
     << "\n - target: " << AS_OBJ(implicit_args[FCA::kTargetIndex])
     << "\n - new_target: " << AS_OBJ(implicit_args[FCA::kNewTargetIndex])
     << "\n - holder: " << AS_OBJ(implicit_args[FCA::kHolderIndex])

     << "\n - argc: " << length  //
     << "\n - receiver: " << AS_OBJ(js_args[0]);

  constexpr int kMaxArgs = 4;
  for (int i = 0; i < std::min(static_cast<int>(length), kMaxArgs); i++) {
    os << "\n - arg[" << i << "]: " << AS_OBJ(js_args[i]);
  }
  os << "\n";
}

void PrintPropertyCallbackInfo(Address* args, std::ostream& os) {
  using PCA = internal::PropertyCallbackArguments;

  static_assert(PCA::kArgsLength == 8);
  os << "PropertyCallbackInfo: "  //
     << "\n - isolate: " << AS_PTR(args[PCA::kIsolateIndex])
     << "\n - return_value: " << AS_OBJ(args[PCA::kReturnValueIndex])
     << "\n - should_throw: " << AS_OBJ(args[PCA::kShouldThrowOnErrorIndex])
     << "\n - holder: " << AS_OBJ(args[PCA::kHolderIndex])
     << "\n - holderV2: " << AS_OBJ(args[PCA::kHolderV2Index])
     << "\n - data: " << AS_OBJ(args[PCA::kDataIndex])  //
     << "\n - property_key: " << AS_OBJ(args[PCA::kPropertyKeyIndex])
     << "\n - receiver: " << AS_OBJ(args[PCA::kThisIndex]);

  // In case it's a setter call there will be additional |value| parameter,
  // print it as a raw pointer to avoid crashing.
  os << "\n - value?: " << AS_PTR(args[PCA::kArgsLength]);
  os << "\n";
}

#undef AS_PTR
#undef AS_OBJ

}  // namespace

void PrintFunctionCallbackInfo(void* function_callback_info) {
  using FCI = v8::FunctionCallbackInfo<v8::Value>;
  FCI& info = *reinterpret_cast<FCI*>(function_callback_info);

  // |values| points to the first argument after the receiver.
  Address* js_args = info.values_ - 1;

  // Output into debugger's command window if a debugger is attached.
  DbgStdoutStream dbg_os;
  PrintFunctionCallbackInfo(info.implicit_args_, js_args, info.length_, dbg_os);
  dbg_os << std::flush;

  StdoutStream os;
  PrintFunctionCallbackInfo(info.implicit_args_, js_args, info.length_, os);
  os << std::flush;
}

void PrintPropertyCallbackInfo(void* property_callback_info) {
  using PCI = v8::PropertyCallbackInfo<v8::Value>;
  PCI& info = *reinterpret_cast<PCI*>(property_callback_info);

  // Output into debugger's command window if a debugger is attached.
  DbgStdoutStream dbg_os;
  PrintPropertyCallbackInfo(info.args_, dbg_os);
  dbg_os << std::flush;

  StdoutStream os;
  PrintPropertyCallbackInfo(info.args_, os);
  os << std::flush;
}

namespace {

void PrintHeapObjectHeaderWithoutMap(Tagged<HeapObject> object,
                                     std::ostream& os, const char* id) {
  PtrComprCageBase cage_base = GetPtrComprCageBase();
  os << reinterpret_cast<void*>(object.ptr()) << ": [";
  if (id != nullptr) {
    os << id;
  } else {
    os << object->map(cage_base)->instance_type();
  }
  os << "]";
  if (ReadOnlyHeap::Contains(object)) {
    os << " in ReadOnlySpace";
  }
}

template <typename T>
void PrintDictionaryContents(std::ostream& os, Tagged<T> dict) {
  DisallowGarbageCollection no_gc;
  ReadOnlyRoots roots = dict->GetReadOnlyRoots();

  if (dict->Capacity() == 0) {
    return;
  }

#ifdef V8_ENABLE_SWISS_NAME_DICTIONARY
  Isolate* isolate = GetIsolateFromWritableObject(dict);
  // IterateEntries for SwissNameDictionary needs to create a handle.
  HandleScope scope(isolate);
#endif
  for (InternalIndex i : dict->IterateEntries()) {
    Tagged<Object> k;
    if (!dict->ToKey(roots, i, &k)) continue;
    os << "\n   ";
    if (IsString(k)) {
      Cast<String>(k)->PrintUC16(os);
    } else {
      os << Brief(k);
    }
    os << ": " << Brief(dict->ValueAt(i)) << " ";
    dict->DetailsAt(i).PrintAsSlowTo(os, !T::kIsOrderedDictionaryType);
  }
}
}  // namespace

void HeapObjectLayout::PrintHeader(std::ostream& os, const char* id) {
  Tagged<HeapObject>(this)->PrintHeader(os, id);
}

void HeapObject::PrintHeader(std::ostream& os, const char* id) {
  PrintHeapObjectHeaderWithoutMap(*this, os, id);
  PtrComprCageBase cage_base = GetPtrComprCageBase();
  if (!SafeEquals(GetReadOnlyRoots().meta_map())) {
    os << "\n - map: " << Brief(map(cage_base));
  }
}

void HeapObject::HeapObjectPrint(std::ostream& os) {
  PtrComprCageBase cage_base = GetPtrComprCageBase();

  InstanceType instance_type = map(cage_base)->instance_type();

  if (instance_type < FIRST_NONSTRING_TYPE) {
    Cast<String>(*this)->StringPrint(os);
    os << "\n";
    return;
  }

  switch (instance_type) {
    case AWAIT_CONTEXT_TYPE:
    case BLOCK_CONTEXT_TYPE:
    case CATCH_CONTEXT_TYPE:
    case DEBUG_EVALUATE_CONTEXT_TYPE:
    case EVAL_CONTEXT_TYPE:
    case FUNCTION_CONTEXT_TYPE:
    case MODULE_CONTEXT_TYPE:
    case SCRIPT_CONTEXT_TYPE:
    case WITH_CONTEXT_TYPE:
      Cast<Context>(*this)->ContextPrint(os);
      break;
    case NATIVE_CONTEXT_TYPE:
      Cast<NativeContext>(*this)->NativeContextPrint(os);
      break;
    case HASH_TABLE_TYPE:
      Cast<ObjectHashTable>(*this)->ObjectHashTablePrint(os);
      break;
    case NAME_TO_INDEX_HASH_TABLE_TYPE:
      Cast<NameToIndexHashTable>(*this)->NameToIndexHashTablePrint(os);
      break;
    case REGISTERED_SYMBOL_TABLE_TYPE:
      Cast<RegisteredSymbolTable>(*this)->RegisteredSymbolTablePrint(os);
      break;
    case ORDERED_HASH_MAP_TYPE:
      Cast<OrderedHashMap>(*this)->OrderedHashMapPrint(os);
      break;
    case ORDERED_HASH_SET_TYPE:
      Cast<OrderedHashSet>(*this)->OrderedHashSetPrint(os);
      break;
    case ORDERED_NAME_DICTIONARY_TYPE:
      Cast<OrderedNameDictionary>(*this)->OrderedNameDictionaryPrint(os);
      break;
    case NAME_DICTIONARY_TYPE:
      Cast<NameDictionary>(*this)->NameDictionaryPrint(os);
      break;
    case GLOBAL_DICTIONARY_TYPE:
      Cast<GlobalDictionary>(*this)->GlobalDictionaryPrint(os);
      break;
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
      Cast<FixedArray>(*this)->FixedArrayPrint(os);
      break;
    case NUMBER_DICTIONARY_TYPE:
      Cast<NumberDictionary>(*this)->NumberDictionaryPrint(os);
      break;
    case EPHEMERON_HASH_TABLE_TYPE:
      Cast<EphemeronHashTable>(*this)->EphemeronHashTablePrint(os);
      break;
    case TRANSITION_ARRAY_TYPE:
      Cast<TransitionArray>(*this)->TransitionArrayPrint(os);
      break;
    case FILLER_TYPE:
      os << "filler";
      break;
    case JS_API_OBJECT_TYPE:
    case JS_ARRAY_ITERATOR_PROTOTYPE_TYPE:
    case JS_CONTEXT_EXTENSION_OBJECT_TYPE:
    case JS_ERROR_TYPE:
    case JS_ITERATOR_PROTOTYPE_TYPE:
    case JS_MAP_ITERATOR_PROTOTYPE_TYPE:
    case JS_OBJECT_PROTOTYPE_TYPE:
    case JS_PROMISE_PROTOTYPE_TYPE:
    case JS_REG_EXP_PROTOTYPE_TYPE:
    case JS_SET_ITERATOR_PROTOTYPE_TYPE:
    case JS_SET_PROTOTYPE_TYPE:
    case JS_SPECIAL_API_OBJECT_TYPE:
    case JS_STRING_ITERATOR_PROTOTYPE_TYPE:
    case JS_TYPED_ARRAY_PROTOTYPE_TYPE:
      Cast<JSObject>(*this)->JSObjectPrint(os);
      break;
#if V8_ENABLE_WEBASSEMBLY
    case WASM_TRUSTED_INSTANCE_DATA_TYPE:
      Cast<WasmTrustedInstanceData>(*this)->WasmTrustedInstanceDataPrint(os);
      break;
    case WASM_DISPATCH_TABLE_TYPE:
      Cast<WasmDispatchTable>(*this)->WasmDispatchTablePrint(os);
      break;
    case WASM_VALUE_OBJECT_TYPE:
      Cast<WasmValueObject>(*this)->WasmValueObjectPrint(os);
      break;
    case WASM_EXCEPTION_PACKAGE_TYPE:
      Cast<WasmExceptionPackage>(*this)->WasmExceptionPackagePrint(os);
      break;
#endif  // V8_ENABLE_WEBASSEMBLY
    case INSTRUCTION_STREAM_TYPE:
      Cast<InstructionStream>(*this)->InstructionStreamPrint(os);
      break;
    case CODE_TYPE:
      Cast<Code>(*this)->CodePrint(os);
      break;
    case CODE_WRAPPER_TYPE:
      Cast<CodeWrapper>(*this)->CodeWrapperPrint(os);
      break;
    case JS_SET_KEY_VALUE_ITERATOR_TYPE:
    case JS_SET_VALUE_ITERATOR_TYPE:
      Cast<JSSetIterator>(*this)->JSSetIteratorPrint(os);
      break;
    case JS_MAP_KEY_ITERATOR_TYPE:
    case JS_MAP_KEY_VALUE_ITERATOR_TYPE:
    case JS_MAP_VALUE_ITERATOR_TYPE:
      Cast<JSMapIterator>(*this)->JSMapIteratorPrint(os);
      break;
#define MAKE_TORQUE_CASE(Name, TYPE)    \
  case TYPE:                            \
    Cast<Name>(*this)->Name##Print(os); \
    break;
      // Every class that has its fields defined in a .tq file and corresponds
      // to exactly one InstanceType value is included in the following list.
      TORQUE_INSTANCE_CHECKERS_SINGLE_FULLY_DEFINED(MAKE_TORQUE_CASE)
      TORQUE_INSTANCE_CHECKERS_MULTIPLE_FULLY_DEFINED(MAKE_TORQUE_CASE)
#undef MAKE_TORQUE_CASE

    case ALLOCATION_SITE_TYPE:
      Cast<AllocationSite>(*this)->AllocationSitePrint(os);
      break;
    case LOAD_HANDLER_TYPE:
      Cast<LoadHandler>(*this)->LoadHandlerPrint(os);
      break;
    case STORE_HANDLER_TYPE:
      Cast<StoreHandler>(*this)->StoreHandlerPrint(os);
      break;
    case FEEDBACK_METADATA_TYPE:
      Cast<FeedbackMetadata>(*this)->FeedbackMetadataPrint(os);
      break;
    case BIG_INT_BASE_TYPE:
      Cast<BigIntBase>(*this)->BigIntBasePrint(os);
      break;
    case JS_CLASS_CONSTRUCTOR_TYPE:
    case JS_PROMISE_CONSTRUCTOR_TYPE:
    case JS_REG_EXP_CONSTRUCTOR_TYPE:
    case JS_ARRAY_CONSTRUCTOR_TYPE:
#define TYPED_ARRAY_CONSTRUCTORS_SWITCH(Type, type, TYPE, Ctype) \
  case TYPE##_TYPED_ARRAY_CONSTRUCTOR_TYPE:
      TYPED_ARRAYS(TYPED_ARRAY_CONSTRUCTORS_SWITCH)
#undef TYPED_ARRAY_CONSTRUCTORS_SWITCH
      Cast<JSFunction>(*this)->JSFunctionPrint(os);
      break;
    case INTERNALIZED_TWO_BYTE_STRING_TYPE:
    case EXTERNAL_INTERNALIZED_TWO_BYTE_STRING_TYPE:
    case INTERNALIZED_ONE_BYTE_STRING_TYPE:
    case EXTERNAL_INTERNALIZED_ONE_BYTE_STRING_TYPE:
    case UNCACHED_EXTERNAL_INTERNALIZED_TWO_BYTE_STRING_TYPE:
    case UNCACHED_EXTERNAL_INTERNALIZED_ONE_BYTE_STRING_TYPE:
    case SEQ_TWO_BYTE_STRING_TYPE:
    case CONS_TWO_BYTE_STRING_TYPE:
    case EXTERNAL_TWO_BYTE_STRING_TYPE:
    case SLICED_TWO_BYTE_STRING_TYPE:
    case THIN_TWO_BYTE_STRING_TYPE:
    case SEQ_ONE_BYTE_STRING_TYPE:
    case CONS_ONE_BYTE_STRING_TYPE:
    case EXTERNAL_ONE_BYTE_STRING_TYPE:
    case SLICED_ONE_BYTE_STRING_TYPE:
    case THIN_ONE_BYTE_STRING_TYPE:
    case UNCACHED_EXTERNAL_TWO_BYTE_STRING_TYPE:
    case UNCACHED_EXTERNAL_ONE_BYTE_STRING_TYPE:
    case SHARED_SEQ_TWO_BYTE_STRING_TYPE:
    case SHARED_SEQ_ONE_BYTE_STRING_TYPE:
    case SHARED_EXTERNAL_TWO_BYTE_STRING_TYPE:
    case SHARED_EXTERNAL_ONE_BYTE_STRING_TYPE:
    case SHARED_UNCACHED_EXTERNAL_TWO_BYTE_STRING_TYPE:
    case SHARED_UNCACHED_EXTERNAL_ONE_BYTE_STRING_TYPE:
    case JS_LAST_DUMMY_API_OBJECT_TYPE:
      // TODO(all): Handle these types too.
      os << "UNKNOWN TYPE " << map()->instance_type();
      UNREACHABLE();
  }
}

template <typename T>
void PrintByteArrayElements(std::ostream& os, const T* array) {
  int length = array->length();
  int i = 0;
  while (i < length) {
    os << "   0x" << std::setfill('0') << std::setw(4) << std::hex << i << ":";
    int line_end = std::min(i + 16, length);
    for (; i < line_end; ++i) {
      os << " " << std::setfill('0') << std::setw(2) << std::hex
         << static_cast<int>(array->get(i));
    }
    os << "\n";
  }
}

void ByteArray::ByteArrayPrint(std::ostream& os) {
  PrintHeader(os, "ByteArray");
  os << "\n - length: " << length()
     << "\n - begin: " << static_cast<void*>(begin()) << "\n";
  PrintByteArrayElements(os, this);
}

void TrustedByteArray::TrustedByteArrayPrint(std::ostream& os) {
  PrintHeader(os, "TrustedByteArray");
  os << "\n - length: " << length()
     << "\n - begin: " << static_cast<void*>(begin()) << "\n";
  PrintByteArrayElements(os, this);
}

void BytecodeArray::BytecodeArrayPrint(std::ostream& os) {
  PrintHeader(os, "BytecodeArray");
  os << "\n";
  Disassemble(os);
}

void BytecodeWrapper::BytecodeWrapperPrint(std::ostream& os) {
  PrintHeader(os, "BytecodeWrapper");
  IsolateForSandbox isolate = GetIsolateForSandbox(*this);
  os << "\n    bytecode: " << Brief(bytecode(isolate));
}

void FreeSpace::FreeSpacePrint(std::ostream& os) {
  os << "free space, size " << Size() << "\n";
}

bool JSObject::PrintProperties(std::ostream& os) {
  if (HasFastProperties()) {
    Tagged<DescriptorArray> descs = map()->instance_descriptors(GetIsolate());
    int nof_inobject_properties = map()->GetInObjectProperties();
    for (InternalIndex i : map()->IterateOwnDescriptors()) {
      os << "\n    ";
      descs->GetKey(i)->NamePrint(os);
      os << ": ";
      PropertyDetails details = descs->GetDetails(i);
      switch (details.location()) {
        case PropertyLocation::kField: {
          FieldIndex field_index = FieldIndex::ForDetails(map(), details);
          os << Brief(RawFastPropertyAt(field_index));
          break;
        }
        case PropertyLocation::kDescriptor:
          os << Brief(descs->GetStrongValue(i));
          break;
      }
      os << " ";
      details.PrintAsFastTo(os, PropertyDetails::kForProperties);
      if (details.location() == PropertyLocation::kField) {
        os << " @ ";
        FieldType::PrintTo(descs->GetFieldType(i), os);
        int field_index = details.field_index();
        if (field_index < nof_inobject_properties) {
          os << ", location: in-object";
        } else {
          field_index -= nof_inobject_properties;
          os << ", location: properties[" << field_index << "]";
        }
      } else {
        os << ", location: descriptor";
      }
    }
    return map()->NumberOfOwnDescriptors() > 0;
  } else if (IsJSGlobalObject(*this)) {
    PrintDictionaryContents(
        os, Cast<JSGlobalObject>(*this)->global_dictionary(kAcquireLoad));
  } else if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    PrintDictionaryContents(os, property_dictionary_swiss());
  } else {
    PrintDictionaryContents(os, property_dictionary());
  }
  return true;
}

namespace {

template <class T>
bool IsTheHoleAt(Tagged<T> array, int index) {
  return false;
}

template <>
bool IsTheHoleAt(Tagged<FixedDoubleArray> array, int index) {
  return array->is_the_hole(index);
}

template <class T>
double GetScalarElement(Tagged<T> array, int index) {
  if (IsTheHoleAt(array, index)) {
    return std::numeric_limits<double>::quiet_NaN();
  }
  return array->get_scalar(index);
}

template <class T>
void DoPrintElements(std::ostream& os, Tagged<Object> object, int length) {
  const bool print_the_hole = std::is_same<T, FixedDoubleArray>::value;
  Tagged<T> array = Cast<T>(object);
  if (length == 0) return;
  int previous_index = 0;
  double previous_value = GetScalarElement(array, 0);
  double value = 0.0;
  int i;
  for (i = 1; i <= length; i++) {
    if (i < length) value = GetScalarElement(array, i);
    bool values_are_nan = std::isnan(previous_value) && std::isnan(value);
    if (i != length && (previous_value == value || values_are_nan) &&
        IsTheHoleAt(array, i - 1) == IsTheHoleAt(array, i)) {
      continue;
    }
    os << "\n";
    std::stringstream ss;
    ss << previous_index;
    if (previous_index != i - 1) {
      ss << '-' << (i - 1);
    }
    os << std::setw(12) << ss.str() << ": ";
    if (print_the_hole && IsTheHoleAt(array, i - 1)) {
      os << "<the_hole>";
    } else {
      os << previous_value;
    }
    previous_index = i;
    previous_value = value;
  }
}

struct Fp16Printer {
  uint16_t val;
  explicit Fp16Printer(float f) : val(fp16_ieee_from_fp32_value(f)) {}
  operator float() const { return fp16_ieee_to_fp32_value(val); }
};

template <typename ElementType>
void PrintTypedArrayElements(std::ostream& os, const ElementType* data_ptr,
                             size_t length, bool is_on_heap) {
  if (length == 0) return;
  size_t previous_index = 0;
  if (i::v8_flags.mock_arraybuffer_allocator && !is_on_heap) {
    // Don't try to print data that's not actually allocated.
    os << "\n    0-" << length << ": <mocked array buffer bytes>";
    return;
  }

  ElementType previous_value = data_ptr[0];
  ElementType value{0};
  for (size_t i = 1; i <= length; i++) {
    if (i < length) value = data_ptr[i];
    if (i != length && previous_value == value) {
      continue;
    }
    os << "\n";
    std::stringstream ss;
    ss << previous_index;
    if (previous_index != i - 1) {
      ss << '-' << (i - 1);
    }
    os << std::setw(12) << ss.str() << ": " << +previous_value;
    previous_index = i;
    previous_value = value;
  }
}

template <typename T>
void PrintFixedArrayElements(std::ostream& os, Tagged<T> array, int capacity,
                             Tagged<Object> (*get)(Tagged<T>, int)) {
  // Print in array notation for non-sparse arrays.
  if (capacity == 0) return;
  Tagged<Object> previous_value = get(array, 0);
  Tagged<Object> value;
  int previous_index = 0;
  int i;
  for (i = 1; i <= capacity; i++) {
    if (i < capacity) value = get(array, i);
    if (previous_value == value && i != capacity) {
      continue;
    }
    os << "\n";
    std::stringstream ss;
    ss << previous_index;
    if (previous_index != i - 1) {
      ss << '-' << (i - 1);
    }
    os << std::setw(12) << ss.str() << ": " << Brief(previous_value);
    previous_index = i;
    previous_value = value;
  }
}

template <typename T>
void PrintFixedArrayElements(std::ostream& os, Tagged<T> array) {
  PrintFixedArrayElements<T>(
      os, array, array->length(),
      [](Tagged<T> xs, int i) { return Cast<Object>(xs->get(i)); });
}

void PrintDictionaryElements(std::ostream& os,
                             Tagged<FixedArrayBase> elements) {
  // Print some internal fields
  Tagged<NumberDictionary> dict = Cast<NumberDictionary>(elements);
  if (dict->requires_slow_elements()) {
    os << "\n   - requires_slow_elements";
  } else {
    os << "\n   - max_number_key: " << dict->max_number_key();
  }
  PrintDictionaryContents(os, dict);
}

void PrintSloppyArgumentElements(std::ostream& os, ElementsKind kind,
                                 Tagged<SloppyArgumentsElements> elements) {
  Tagged<FixedArray> arguments_store = elements->arguments();
  os << "\n    0: context: " << Brief(elements->context())
     << "\n    1: arguments_store: " << Brief(arguments_store)
     << "\n    parameter to context slot map:";
  for (int i = 0; i < elements->length(); i++) {
    Tagged<Object> mapped_entry = elements->mapped_entries(i, kRelaxedLoad);
    os << "\n    " << i << ": param(" << i << "): " << Brief(mapped_entry);
    if (IsTheHole(mapped_entry)) {
      os << " in the arguments_store[" << i << "]";
    } else {
      os << " in the context";
    }
  }
  if (arguments_store->length() == 0) return;
  os << "\n }"
     << "\n - arguments_store: " << Brief(arguments_store) << " "
     << ElementsKindToString(arguments_store->map()->elements_kind()) << " {";
  if (kind == FAST_SLOPPY_ARGUMENTS_ELEMENTS) {
    PrintFixedArrayElements(os, arguments_store);
  } else {
    DCHECK_EQ(kind, SLOW_SLOPPY_ARGUMENTS_ELEMENTS);
    PrintDictionaryElements(os, arguments_store);
  }
}

void PrintEmbedderData(IsolateForSandbox isolate, std::ostream& os,
                       EmbedderDataSlot slot) {
  DisallowGarbageCollection no_gc;
  Tagged<Object> value = slot.load_tagged();
  os << Brief(value);
  void* raw_pointer;
  if (slot.ToAlignedPointer(isolate, &raw_pointer)) {
    os << ", aligned pointer: " << raw_pointer;
  }
}

}  // namespace

void JSObject::PrintElements(std::ostream& os) {
  // Don't call GetElementsKind, its validation code can cause the printer to
  // fail when debugging.
  os << " - elements: " << Brief(elements()) << " {";
  switch (map()->elements_kind()) {
    case HOLEY_SMI_ELEMENTS:
    case PACKED_SMI_ELEMENTS:
    case HOLEY_ELEMENTS:
    case HOLEY_FROZEN_ELEMENTS:
    case HOLEY_SEALED_ELEMENTS:
    case HOLEY_NONEXTENSIBLE_ELEMENTS:
    case PACKED_ELEMENTS:
    case PACKED_FROZEN_ELEMENTS:
    case PACKED_SEALED_ELEMENTS:
    case PACKED_NONEXTENSIBLE_ELEMENTS:
    case FAST_STRING_WRAPPER_ELEMENTS:
    case SHARED_ARRAY_ELEMENTS: {
      PrintFixedArrayElements(os, Cast<FixedArray>(elements()));
      break;
    }
    case HOLEY_DOUBLE_ELEMENTS:
    case PACKED_DOUBLE_ELEMENTS: {
      DoPrintElements<FixedDoubleArray>(os, elements(), elements()->length());
      break;
    }

#define PRINT_ELEMENTS(Type, type, TYPE, elementType)                          \
  case TYPE##_ELEMENTS: {                                                      \
    size_t length = Cast<JSTypedArray>(*this)->GetLength();                    \
    bool is_on_heap = Cast<JSTypedArray>(*this)->is_on_heap();                 \
    const elementType* data_ptr =                                              \
        static_cast<const elementType*>(Cast<JSTypedArray>(*this)->DataPtr()); \
    PrintTypedArrayElements<elementType>(os, data_ptr, length, is_on_heap);    \
    break;                                                                     \
  }
      TYPED_ARRAYS(PRINT_ELEMENTS)
      RAB_GSAB_TYPED_ARRAYS(PRINT_ELEMENTS)
#undef PRINT_ELEMENTS

    case DICTIONARY_ELEMENTS:
    case SLOW_STRING_WRAPPER_ELEMENTS:
      PrintDictionaryElements(os, elements());
      break;
    case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
    case SLOW_SLOPPY_ARGUMENTS_ELEMENTS:
      PrintSloppyArgumentElements(os, map()->elements_kind(),
                                  Cast<SloppyArgumentsElements>(elements()));
      break;
    case WASM_ARRAY_ELEMENTS:
      // WasmArrayPrint() should be called intead.
      UNREACHABLE();
    case NO_ELEMENTS:
      break;
  }
  os << "\n }\n";
}

namespace {

void JSObjectPrintHeader(std::ostream& os, Tagged<JSObject> obj,
                         const char* id) {
  Isolate* isolate = obj->GetIsolate();
  obj->PrintHeader(os, id);
  // Don't call GetElementsKind, its validation code can cause the printer to
  // fail when debugging.
  os << " [";
  if (obj->HasFastProperties()) {
    os << "FastProperties";
  } else {
    os << "DictionaryProperties";
  }
  PrototypeIterator iter(isolate, obj);
  os << "]\n - prototype: " << Brief(iter.GetCurrent());
  os << "\n - elements: " << Brief(obj->elements()) << " ["
     << ElementsKindToString(obj->map()->elements_kind());
  if (obj->elements()->IsCowArray()) os << " (COW)";
  os << "]";
  Tagged<Object> hash = Object::GetHash(obj);
  if (IsSmi(hash)) {
    os << "\n - hash: " << Brief(hash);
  }
  if (obj->GetEmbedderFieldCount() > 0) {
    os << "\n - embedder fields: " << obj->GetEmbedderFieldCount();
  }
}

void JSAPIObjectWithEmbedderSlotsPrintHeader(std::ostream& os,
                                             Tagged<JSObject> obj,
                                             const char* id = nullptr) {
  JSObjectPrintHeader(os, obj, id);
  os << "\n - cpp_heap_wrappable: "
     << obj->ReadField<uint32_t>(
            JSAPIObjectWithEmbedderSlots::kCppHeapWrappableOffset);
}

void JSObjectPrintBody(std::ostream& os, Tagged<JSObject> obj,
                       bool print_elements = true) {
  os << "\n - properties: ";
  Tagged<Object> properties_or_hash = obj->raw_properties_or_hash(kRelaxedLoad);
  if (!IsSmi(properties_or_hash)) {
    os << Brief(properties_or_hash);
  }
  os << "\n - All own properties (excluding elements): {";
  if (obj->PrintProperties(os)) os << "\n ";
  os << "}\n";

  if (print_elements) {
    size_t length = IsJSTypedArray(obj) ? Cast<JSTypedArray>(obj)->GetLength()
                                        : obj->elements()->length();
    if (length > 0) obj->PrintElements(os);
  }
  int embedder_fields = obj->GetEmbedderFieldCount();
  if (embedder_fields > 0) {
    IsolateForSandbox isolate = GetIsolateForSandbox(obj);
    os << " - embedder fields = {";
    for (int i = 0; i < embedder_fields; i++) {
      os << "\n    ";
      PrintEmbedderData(isolate, os, EmbedderDataSlot(obj, i));
    }
    os << "\n }\n";
  }
}

}  // namespace

void JSObject::JSObjectPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, nullptr);
  JSObjectPrintBody(os, *this);
}

void JSExternalObject::JSExternalObjectPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, nullptr);
  os << "\n - external value: " << value();
  JSObjectPrintBody(os, *this);
}

void JSGeneratorObject::JSGeneratorObjectPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSGeneratorObject");
  os << "\n - function: " << Brief(function());
  os << "\n - context: " << Brief(context());
  os << "\n - receiver: " << Brief(receiver());
  if (is_executing() || is_closed()) {
    os << "\n - input: " << Brief(input_or_debug_pos());
  } else {
    DCHECK(is_suspended());
    os << "\n - debug pos: " << Brief(input_or_debug_pos());
  }
  const char* mode = "(invalid)";
  switch (resume_mode()) {
    case kNext:
      mode = ".next()";
      break;
    case kReturn:
      mode = ".return()";
      break;
    case kThrow:
      mode = ".throw()";
      break;
  }
  os << "\n - resume mode: " << mode;
  os << "\n - continuation: " << continuation();
  if (is_closed()) os << " (closed)";
  if (is_executing()) os << " (executing)";
  if (is_suspended()) os << " (suspended)";
  if (is_suspended()) {
    DisallowGarbageCollection no_gc;
    Tagged<SharedFunctionInfo> fun_info = function()->shared();
    if (fun_info->HasSourceCode()) {
      Tagged<Script> script = Cast<Script>(fun_info->script());
      Tagged<String> script_name = IsString(script->name())
                                       ? Cast<String>(script->name())
                                       : GetReadOnlyRoots().empty_string();

      os << "\n - source position: ";
      // Can't collect source positions here if not available as that would
      // allocate memory.
      Isolate* isolate = GetIsolate();
      if (fun_info->HasBytecodeArray() &&
          fun_info->GetBytecodeArray(isolate)->HasSourcePositionTable()) {
        os << source_position();
        os << " (";
        script_name->PrintUC16(os);
        Script::PositionInfo info;
        script->GetPositionInfo(source_position(), &info);
        os << ", line " << info.line + 1;
        os << ", column " << info.column + 1;
      } else {
        os << kUnavailableString;
      }
      os << ")";
    }
  }
  os << "\n - register file: " << Brief(parameters_and_registers());
  JSObjectPrintBody(os, *this);
}

void JSArray::JSArrayPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSArray");
  os << "\n - length: " << Brief(this->length());
  JSObjectPrintBody(os, *this);
}

void JSPromise::JSPromisePrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSPromise");
  os << "\n - status: " << JSPromise::Status(status());
  if (status() == Promise::kPending) {
    os << "\n - reactions: " << Brief(reactions());
  } else {
    os << "\n - result: " << Brief(result());
  }
  os << "\n - has_handler: " << has_handler();
  os << "\n - is_silent: " << is_silent();
  JSObjectPrintBody(os, *this);
}

void JSRegExp::JSRegExpPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSRegExp");
  IsolateForSandbox isolate = GetIsolateForSandbox(*this);
  os << "\n - data: " << Brief(data(isolate));
  os << "\n - source: " << Brief(source());
  FlagsBuffer buffer;
  os << "\n - flags: " << JSRegExp::FlagsToString(flags(), &buffer);
  JSObjectPrintBody(os, *this);
}

void RegExpData::RegExpDataPrint(std::ostream& os) {
  switch (type_tag()) {
    case RegExpData::Type::ATOM:
      PrintHeader(os, "AtomRegExpData");
      break;
    case RegExpData::Type::IRREGEXP:
      PrintHeader(os, "IrRegExpData");
      break;
    case RegExpData::Type::EXPERIMENTAL:
      PrintHeader(os, "IrRegExpData");
      break;
    default:
      UNREACHABLE();
  }
  os << "\n - source: " << source();
  JSRegExp::FlagsBuffer buffer;
  os << "\n - flags: " << JSRegExp::FlagsToString(flags(), &buffer);
}

void AtomRegExpData::AtomRegExpDataPrint(std::ostream& os) {
  RegExpDataPrint(os);
  os << "\n - pattern: " << pattern();
  os << "\n";
}

void IrRegExpData::IrRegExpDataPrint(std::ostream& os) {
  IsolateForSandbox isolate = GetIsolateForSandbox(*this);
  RegExpDataPrint(os);
  if (has_latin1_bytecode()) {
    os << "\n - latin1_bytecode: " << Brief(latin1_bytecode());
  }
  if (has_uc16_bytecode()) {
    os << "\n - uc16_bytecode: " << Brief(uc16_bytecode());
  }
  if (has_latin1_code()) {
    os << "\n - latin1_code: " << Brief(latin1_code(isolate));
  }
  if (has_uc16_code()) {
    os << "\n - uc16_code: " << Brief(uc16_code(isolate));
  }
  os << "\n - capture_name_map: " << Brief(capture_name_map());
  os << "\n - max_register_count: " << max_register_count();
  os << "\n - capture_count: " << max_register_count();
  os << "\n - ticks_until_tier_up: " << max_register_count();
  os << "\n - backtrack_limit: " << max_register_count();
  os << "\n";
}

void RegExpDataWrapper::RegExpDataWrapperPrint(std::ostream& os) {
  PrintHeader(os, "RegExpDataWrapper");
  IsolateForSandbox isolate = GetIsolateForSandbox(*this);
  os << "\n    data: " << Brief(data(isolate));
  os << "\n";
}

void JSRegExpStringIterator::JSRegExpStringIteratorPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSRegExpStringIterator");
  os << "\n - regex: " << Brief(iterating_reg_exp());
  os << "\n - string: " << Brief(iterated_string());
  os << "\n - done: " << done();
  os << "\n - global: " << global();
  os << "\n - unicode: " << unicode();
  JSObjectPrintBody(os, *this);
}

void Symbol::SymbolPrint(std::ostream& os) {
  PrintHeader(os, "Symbol");
  os << "\n - hash: " << hash();
  os << "\n - description: " << Brief(description());
  if (IsUndefined(description())) {
    os << " (" << PrivateSymbolToName() << ")";
  }
  os << "\n - private: " << is_private();
  os << "\n - private_name: " << is_private_name();
  os << "\n - private_brand: " << is_private_brand();
  os << "\n - is_interesting_symbol: " << is_interesting_symbol();
  os << "\n - is_well_known_symbol: " << is_well_known_symbol();
  os << "\n";
}

void DescriptorArray::DescriptorArrayPrint(std::ostream& os) {
  PrintHeader(os, "DescriptorArray");
  os << "\n - enum_cache: ";
  if (enum_cache()->keys()->length() == 0) {
    os << "empty";
  } else {
    os << enum_cache()->keys()->length();
    os << "\n   - keys: " << Brief(enum_cache()->keys());
    os << "\n   - indices: " << Brief(enum_cache()->indices());
  }
  os << "\n - nof slack descriptors: " << number_of_slack_descriptors();
  os << "\n - nof descriptors: " << number_of_descriptors();
  const auto raw = raw_gc_state(kRelaxedLoad);
  os << "\n - raw gc state: mc epoch "
     << DescriptorArrayMarkingState::Epoch::decode(raw) << ", marked "
     << DescriptorArrayMarkingState::Marked::decode(raw) << ", delta "
     << DescriptorArrayMarkingState::Delta::decode(raw);
  PrintDescriptors(os);
}

namespace {
template <typename T>
void PrintFixedArrayWithHeader(std::ostream& os, T* array, const char* type) {
  array->PrintHeader(os, type);
  os << "\n - length: " << array->length();
  PrintFixedArrayElements(os, Tagged(array));
  os << "\n";
}

template <typename T>
void PrintWeakArrayElements(std::ostream& os, T* array) {
  // Print in array notation for non-sparse arrays.
  Tagged<MaybeObject> previous_value =
      array->length() > 0 ? array->get(0) : Tagged<MaybeObject>(kNullAddress);
  Tagged<MaybeObject> value;
  int previous_index = 0;
  int i;
  for (i = 1; i <= array->length(); i++) {
    if (i < array->length()) value = array->get(i);
    if (previous_value == value && i != array->length()) {
      continue;
    }
    os << "\n";
    std::stringstream ss;
    ss << previous_index;
    if (previous_index != i - 1) {
      ss << '-' << (i - 1);
    }
    os << std::setw(12) << ss.str() << ": " << Brief(previous_value);
    previous_index = i;
    previous_value = value;
  }
}

}  // namespace

void ObjectBoilerplateDescription::ObjectBoilerplateDescriptionPrint(
    std::ostream& os) {
  PrintHeader(os, "ObjectBoilerplateDescription");
  os << "\n - capacity: " << capacity();
  os << "\n - backing_store_size: " << backing_store_size();
  os << "\n - flags: " << flags();
  os << "\n - elements:";
  PrintFixedArrayElements<ObjectBoilerplateDescription>(
      os, this, capacity(), [](Tagged<ObjectBoilerplateDescription> xs, int i) {
        return xs->get(i);
      });
  os << "\n";
}

void ClassBoilerplate::ClassBoilerplatePrint(std::ostream& os) {
  PrintHeader(os, "ClassBoilerplate");
  os << "\n - arguments_count: " << arguments_count();
  os << "\n - static_properties_template: " << static_properties_template();
  os << "\n - static_elements_template: " << static_elements_template();
  os << "\n - static_computed_properties: " << static_computed_properties();
  os << "\n - instance_properties_template: " << instance_properties_template();
  os << "\n - instance_elements_template: " << instance_elements_template();
  os << "\n - instance_computed_properties: " << instance_computed_properties();
  os << "\n";
}

void RegExpBoilerplateDescription::RegExpBoilerplateDescriptionPrint(
    std::ostream& os) {
  IsolateForSandbox isolate = GetIsolateForSandbox(*this);
  PrintHeader(os, "RegExpBoilerplate");
  os << "\n - data: " << Brief(data(isolate));
  os << "\n - source: " << source();
  os << "\n - flags: " << flags();
  os << "\n";
}

void EmbedderDataArray::EmbedderDataArrayPrint(std::ostream& os) {
  IsolateForSandbox isolate = GetIsolateForSandbox(*this);
  PrintHeader(os, "EmbedderDataArray");
  os << "\n - length: " << length();
  EmbedderDataSlot start(*this, 0);
  EmbedderDataSlot end(*this, length());
  for (EmbedderDataSlot slot = start; slot < end; ++slot) {
    os << "\n    ";
    PrintEmbedderData(isolate, os, slot);
  }
  os << "\n";
}

void FixedArray::FixedArrayPrint(std::ostream& os) {
  PrintFixedArrayWithHeader(os, this, "FixedArray");
}

void TrustedFixedArray::TrustedFixedArrayPrint(std::ostream& os) {
  PrintFixedArrayWithHeader(os, this, "TrustedFixedArray");
}

void ProtectedFixedArray::ProtectedFixedArrayPrint(std::ostream& os) {
  PrintFixedArrayWithHeader(os, this, "ProtectedFixedArray");
}

void ArrayList::ArrayListPrint(std::ostream& os) {
  PrintHeader(os, "ArrayList");
  os << "\n - capacity: " << capacity();
  os << "\n - length: " << length();
  os << "\n - elements:";
  PrintFixedArrayElements<ArrayList>(
      os, this, length(),
      [](Tagged<ArrayList> xs, int i) { return xs->get(i); });
  os << "\n";
}

void ScriptContextTable::ScriptContextTablePrint(std::ostream& os) {
  PrintHeader(os, "ScriptContextTable");
  os << "\n - capacity: " << capacity();
  os << "\n - length: " << length(kAcquireLoad);
  os << "\n - names_to_context_index: " << names_to_context_index();
  os << "\n - elements:";
  PrintFixedArrayElements<ScriptContextTable>(
      os, this, length(kAcquireLoad), [](Tagged<ScriptContextTable> xs, int i) {
        return Cast<Object>(xs->get(i));
      });
  os << "\n";
}

void RegExpMatchInfo::RegExpMatchInfoPrint(std::ostream& os) {
  PrintHeader(os, "RegExpMatchInfo");
  os << "\n - capacity: " << capacity();
  os << "\n - number_of_capture_registers: " << number_of_capture_registers();
  os << "\n - last_subject: " << last_subject();
  os << "\n - last_input: " << last_input();
  os << "\n - captures:";
  PrintFixedArrayElements<RegExpMatchInfo>(
      os, this, capacity(), [](Tagged<RegExpMatchInfo> xs, int i) {
        return Cast<Object>(xs->get(i));
      });
  os << "\n";
}

void SloppyArgumentsElements::SloppyArgumentsElementsPrint(std::ostream& os) {
  PrintHeader(os, "SloppyArgumentsElements");
  os << "\n - length: " << length();
  os << "\n - context: " << Brief(context());
  os << "\n - arguments: " << Brief(arguments());
  os << "\n - mapped_entries:";
  PrintFixedArrayElements<SloppyArgumentsElements>(
      os, this, length(), [](Tagged<SloppyArgumentsElements> xs, int i) {
        return Cast<Object>(xs->mapped_entries(i, kRelaxedLoad));
      });
  os << '\n';
}

namespace {
const char* SideEffectType2String(SideEffectType type) {
  switch (type) {
    case SideEffectType::kHasSideEffect:
      return "kHasSideEffect";
    case SideEffectType::kHasNoSideEffect:
      return "kHasNoSideEffect";
    case SideEffectType::kHasSideEffectToReceiver:
      return "kHasSideEffectToReceiver";
  }
}
}  // namespace

void AccessorInfo::AccessorInfoPrint(std::ostream& os) {
  TorqueGeneratedAccessorInfo<AccessorInfo, HeapObject>::AccessorInfoPrint(os);
  os << " - is_sloppy: " << is_sloppy();
  os << "\n - replace_on_access: " << replace_on_access();
  os << "\n - getter_side_effect_type: "
     << SideEffectType2String(getter_side_effect_type());
  os << "\n - setter_side_effect_type: "
     << SideEffectType2String(setter_side_effect_type());
  os << "\n - initial_attributes: " << initial_property_attributes();
  Isolate* isolate;
  if (GetIsolateFromHeapObject(*this, &isolate)) {
    os << "\n - getter: " << reinterpret_cast<void*>(getter(isolate));
    if (USE_SIMULATOR_BOOL) {
      os << "\n - maybe_redirected_getter: "
         << reinterpret_cast<void*>(maybe_redirected_getter(isolate));
    }
    os << "\n - setter: " << reinterpret_cast<void*>(setter(isolate));
  } else {
    os << "\n - getter: " << kUnavailableString;
    os << "\n - maybe_redirected_getter: " << kUnavailableString;
    os << "\n - setter: " << kUnavailableString;
  }
  os << '\n';
}

void FunctionTemplateInfo::FunctionTemplateInfoPrint(std::ostream& os) {
  TorqueGeneratedFunctionTemplateInfo<
      FunctionTemplateInfo, TemplateInfo>::FunctionTemplateInfoPrint(os);

  Isolate* isolate;
  if (GetIsolateFromHeapObject(*this, &isolate)) {
    os << " - callback: " << reinterpret_cast<void*>(callback(isolate));
    if (USE_SIMULATOR_BOOL) {
      os << "\n - maybe_redirected_callback: "
         << reinterpret_cast<void*>(maybe_redirected_callback(isolate));
    }
  } else {
    os << "\n - callback: " << kUnavailableString;
    os << "\n - maybe_redirected_callback: " << kUnavailableString;
  }

  os << "\n --- flags: ";
  if (is_object_template_call_handler()) {
    os << "\n - is_object_template_call_handler";
  }
  if (has_side_effects()) os << "\n - has_side_effects";

  if (undetectable()) os << "\n - undetectable";
  if (needs_access_check()) os << "\n - needs_access_check";
  if (read_only_prototype()) os << "\n - read_only_prototype";
  if (remove_prototype()) os << "\n - remove_prototype";
  if (accept_any_receiver()) os << "\n - accept_any_receiver";
  if (published()) os << "\n - published";

  if (allowed_receiver_instance_type_range_start() ||
      allowed_receiver_instance_type_range_end()) {
    os << "\n - allowed_receiver_instance_type_range: ["
       << allowed_receiver_instance_type_range_start() << ", "
       << allowed_receiver_instance_type_range_end() << "]";
  }
  os << '\n';
}

namespace {
void PrintContextWithHeader(std::ostream& os, Tagged<Context> context,
                            const char* type) {
  context->PrintHeader(os, type);
  os << "\n - type: " << context->map()->instance_type();
  os << "\n - scope_info: " << Brief(context->scope_info());
  os << "\n - previous: " << Brief(context->unchecked_previous());
  os << "\n - native_context: " << Brief(context->native_context());
  if (context->scope_info()->HasContextExtensionSlot()) {
    os << "\n - extension: " << context->extension();
  }
  os << "\n - length: " << context->length();
  os << "\n - elements:";
  PrintFixedArrayElements(os, context);
  os << "\n";
}
}  // namespace

void Context::ContextPrint(std::ostream& os) {
  PrintContextWithHeader(os, *this, "Context");
}

void NativeContext::NativeContextPrint(std::ostream& os) {
  PrintContextWithHeader(os, *this, "NativeContext");
  os << " - microtask_queue: " << microtask_queue() << "\n";
}

namespace {
using DataPrinter = std::function<void(InternalIndex)>;

// Prints the data associated with each key (but no headers or other meta
// data) in a hash table. Works on different hash table types, like the
// subtypes of HashTable and OrderedHashTable. |print_data_at| is given an
// index into the table (where a valid key resides) and prints the data at
// that index, like just the value (in case of a hash map), or value and
// property details (in case of a property dictionary). No leading space
// required or trailing newline required. It can be null/non-callable
// std::function to indicate that there is no associcated data to be printed
// (for example in case of a hash set).
template <typename T>
void PrintTableContentsGeneric(std::ostream& os, T* dict,
                               DataPrinter print_data_at) {
  DisallowGarbageCollection no_gc;
  ReadOnlyRoots roots = dict->GetReadOnlyRoots();

  for (InternalIndex i : dict->IterateEntries()) {
    Tagged<Object> k;
    if (!dict->ToKey(roots, i, &k)) continue;
    os << "\n   " << std::setw(12) << i.as_int() << ": ";
    if (IsString(k)) {
      Cast<String>(k)->PrintUC16(os);
    } else {
      os << Brief(k);
    }
    if (print_data_at) {
      os << " -> ";
      print_data_at(i);
    }
  }
}

void PrintNameDictionaryFlags(std::ostream& os, Tagged<NameDictionary> dict) {
  if (dict->may_have_interesting_properties()) {
    os << "\n - may_have_interesting_properties";
  }
}

// Used for ordered and unordered dictionaries.
template <typename T>
void PrintDictionaryContentsFull(std::ostream& os, T* dict) {
  os << "\n - elements: {";
  auto print_value_and_property_details = [&](InternalIndex i) {
    os << Brief(dict->ValueAt(i)) << " ";
    dict->DetailsAt(i).PrintAsSlowTo(os, !T::kIsOrderedDictionaryType);
  };
  PrintTableContentsGeneric(os, dict, print_value_and_property_details);
  os << "\n }\n";
}

// Used for ordered and unordered hash maps.
template <typename T>
void PrintHashMapContentsFull(std::ostream& os, T* dict) {
  os << "\n - elements: {";
  auto print_value = [&](InternalIndex i) { os << Brief(dict->ValueAt(i)); };
  PrintTableContentsGeneric(os, dict, print_value);
  os << "\n }\n";
}

// Used for ordered and unordered hash sets.
template <typename T>
void PrintHashSetContentsFull(std::ostream& os, T* dict) {
  os << "\n - elements: {";
  // Passing non-callable std::function as there are no values to print.
  PrintTableContentsGeneric(os, dict, nullptr);
  os << "\n }\n";
}

// Used for subtypes of OrderedHashTable.
template <typename T>
void PrintOrderedHashTableHeaderAndBuckets(std::ostream& os, T* table,
                                           const char* type) {
  DisallowGarbageCollection no_gc;

  PrintHeapObjectHeaderWithoutMap(table, os, type);
  os << "\n - FixedArray length: " << table->length();
  os << "\n - elements: " << table->NumberOfElements();
  os << "\n - deleted: " << table->NumberOfDeletedElements();
  os << "\n - buckets: " << table->NumberOfBuckets();
  os << "\n - capacity: " << table->Capacity();

  os << "\n - buckets: {";
  for (int bucket = 0; bucket < table->NumberOfBuckets(); bucket++) {
    Tagged<Object> entry = table->get(T::HashTableStartIndex() + bucket);
    DCHECK(IsSmi(entry));
    os << "\n   " << std::setw(12) << bucket << ": " << Brief(entry);
  }
  os << "\n }";
}

// Used for subtypes of HashTable.
template <typename T>
void PrintHashTableHeader(std::ostream& os, T* table, const char* type) {
  PrintHeapObjectHeaderWithoutMap(table, os, type);
  os << "\n - FixedArray length: " << table->length();
  os << "\n - elements: " << table->NumberOfElements();
  os << "\n - deleted: " << table->NumberOfDeletedElements();
  os << "\n - capacity: " << table->Capacity();
}
}  // namespace

void ObjectHashTable::ObjectHashTablePrint(std::ostream& os) {
  PrintHashTableHeader(os, this, "ObjectHashTable");
  PrintHashMapContentsFull(os, this);
}

void NameToIndexHashTable::NameToIndexHashTablePrint(std::ostream& os) {
  PrintHashTableHeader(os, this, "NameToIndexHashTable");
  PrintHashMapContentsFull(os, this);
}

void RegisteredSymbolTable::RegisteredSymbolTablePrint(std::ostream& os) {
  PrintHashTableHeader(os, this, "RegisteredSymbolTable");
  PrintHashMapContentsFull(os, this);
}

void NumberDictionary::NumberDictionaryPrint(std::ostream& os) {
  PrintHashTableHeader(os, this, "NumberDictionary");
  PrintDictionaryContentsFull(os, this);
}

void EphemeronHashTable::EphemeronHashTablePrint(std::ostream& os) {
  PrintHashTableHeader(os, this, "EphemeronHashTable");
  PrintHashMapContentsFull(os, this);
}

void NameDictionary::NameDictionaryPrint(std::ostream& os) {
  PrintHashTableHeader(os, this, "NameDictionary");
  PrintNameDictionaryFlags(os, this);
  PrintDictionaryContentsFull(os, this);
}

void GlobalDictionary::GlobalDictionaryPrint(std::ostream& os) {
  PrintHashTableHeader(os, this, "GlobalDictionary");
  PrintDictionaryContentsFull(os, this);
}

void SmallOrderedHashSet::SmallOrderedHashSetPrint(std::ostream& os) {
  PrintHeader(os, "SmallOrderedHashSet");
  // TODO(turbofan): Print all fields.
}

void SmallOrderedHashMap::SmallOrderedHashMapPrint(std::ostream& os) {
  PrintHeader(os, "SmallOrderedHashMap");
  // TODO(turbofan): Print all fields.
}

void SmallOrderedNameDictionary::SmallOrderedNameDictionaryPrint(
    std::ostream& os) {
  PrintHeader(os, "SmallOrderedNameDictionary");
  // TODO(turbofan): Print all fields.
}

void OrderedHashSet::OrderedHashSetPrint(std::ostream& os) {
  PrintOrderedHashTableHeaderAndBuckets(os, this, "OrderedHashSet");
  PrintHashSetContentsFull(os, this);
}

void OrderedHashMap::OrderedHashMapPrint(std::ostream& os) {
  PrintOrderedHashTableHeaderAndBuckets(os, this, "OrderedHashMap");
  PrintHashMapContentsFull(os, this);
}

void OrderedNameDictionary::OrderedNameDictionaryPrint(std::ostream& os) {
  PrintOrderedHashTableHeaderAndBuckets(os, this, "OrderedNameDictionary");
  PrintDictionaryContentsFull(os, this);
}

void print_hex_byte(std::ostream& os, int value) {
  os << "0x" << std::setfill('0') << std::setw(2) << std::right << std::hex
     << (value & 0xff) << std::setfill(' ');
}

void SwissNameDictionary::SwissNameDictionaryPrint(std::ostream& os) {
  this->PrintHeader(os, "SwissNameDictionary");
  os << "\n - meta table ByteArray: "
     << reinterpret_cast<void*>(this->meta_table().ptr());
  os << "\n - capacity: " << this->Capacity();
  os << "\n - elements: " << this->NumberOfElements();
  os << "\n - deleted: " << this->NumberOfDeletedElements();

  std::ios_base::fmtflags sav_flags = os.flags();
  os << "\n - ctrl table (omitting buckets where key is hole value): {";
  for (int i = 0; i < this->Capacity() + kGroupWidth; i++) {
    ctrl_t ctrl = CtrlTable()[i];

    if (ctrl == Ctrl::kEmpty) continue;

    os << "\n   " << std::setw(12) << std::dec << i << ": ";
    switch (ctrl) {
      case Ctrl::kEmpty:
        UNREACHABLE();
      case Ctrl::kDeleted:
        print_hex_byte(os, ctrl);
        os << " (= kDeleted)";
        break;
      case Ctrl::kSentinel:
        print_hex_byte(os, ctrl);
        os << " (= kSentinel)";
        break;
      default:
        print_hex_byte(os, ctrl);
        os << " (= H2 of a key)";
        break;
    }
  }
  os << "\n }";

  os << "\n - enumeration table: {";
  for (int enum_index = 0; enum_index < this->UsedCapacity(); enum_index++) {
    int entry = EntryForEnumerationIndex(enum_index);
    os << "\n   " << std::setw(12) << std::dec << enum_index << ": " << entry;
  }
  os << "\n }";

  os << "\n - data table (omitting slots where key is the hole): {";
  for (int bucket = 0; bucket < this->Capacity(); ++bucket) {
    Tagged<Object> k;
    if (!this->ToKey(this->GetReadOnlyRoots(), bucket, &k)) continue;

    Tagged<Object> value = this->ValueAtRaw(bucket);
    PropertyDetails details = this->DetailsAt(bucket);
    os << "\n   " << std::setw(12) << std::dec << bucket << ": ";
    if (IsString(k)) {
      Cast<String>(k)->PrintUC16(os);
    } else {
      os << Brief(k);
    }
    os << " -> " << Brief(value);
    details.PrintAsSlowTo(os, false);
  }
  os << "\n }\n";
  os.flags(sav_flags);
}

void PropertyArray::PropertyArrayPrint(std::ostream& os) {
  PrintHeader(os, "PropertyArray");
  os << "\n - length: " << length();
  os << "\n - hash: " << Hash();
  PrintFixedArrayElements(os, Tagged(*this));
  os << "\n";
}

void FixedDoubleArray::FixedDoubleArrayPrint(std::ostream& os) {
  PrintHeader(os, "FixedDoubleArray");
  os << "\n - length: " << length();
  DoPrintElements<FixedDoubleArray>(os, this, length());
  os << "\n";
}

void WeakFixedArray::WeakFixedArrayPrint(std::ostream& os) {
  PrintHeader(os, "WeakFixedArray");
  os << "\n - length: " << length();
  PrintWeakArrayElements(os, this);
  os << "\n";
}

void TrustedWeakFixedArray::TrustedWeakFixedArrayPrint(std::ostream& os) {
  PrintHeader(os, "TrustedWeakFixedArray");
  os << "\n - length: " << length();
  PrintWeakArrayElements(os, this);
  os << "\n";
}

void WeakArrayList::WeakArrayListPrint(std::ostream& os) {
  PrintHeader(os, "WeakArrayList");
  os << "\n - capacity: " << capacity();
  os << "\n - length: " << length();
  PrintWeakArrayElements(os, this);
  os << "\n";
}

void TransitionArray::TransitionArrayPrint(std::ostream& os) {
  PrintHeader(os, "TransitionArray");
  PrintInternal(os);
  os << "\n";
}

void FeedbackCell::FeedbackCellPrint(std::ostream& os) {
  PrintHeader(os, "FeedbackCell");
  ReadOnlyRoots roots = GetReadOnlyRoots();
  if (map() == roots.no_closures_cell_map()) {
    os << "\n - no closures";
  } else if (map() == roots.one_closure_cell_map()) {
    os << "\n - one closure";
  } else if (map() == roots.many_closures_cell_map()) {
    os << "\n - many closures";
  } else {
    os << "\n - Invalid FeedbackCell map";
  }
  os << "\n - value: " << Brief(value());
  os << "\n - interrupt_budget: " << interrupt_budget();
  os << "\n";
}

void FeedbackVectorSpec::Print() {
  StdoutStream os;

  FeedbackVectorSpecPrint(os);

  os << std::flush;
}

void FeedbackVectorSpec::FeedbackVectorSpecPrint(std::ostream& os) {
  os << " - slot_count: " << slot_count();
  if (slot_count() == 0) {
    os << " (empty)\n";
    return;
  }

  for (int slot = 0; slot < slot_count();) {
    FeedbackSlotKind kind = GetKind(FeedbackSlot(slot));
    int entry_size = FeedbackMetadata::GetSlotSize(kind);
    DCHECK_LT(0, entry_size);
    os << "\n Slot #" << slot << " " << kind;
    slot += entry_size;
  }
  os << "\n";
}

void FeedbackMetadata::FeedbackMetadataPrint(std::ostream& os) {
  PrintHeader(os, "FeedbackMetadata");
  os << "\n - slot_count: " << slot_count();
  os << "\n - create_closure_slot_count: " << create_closure_slot_count();

  FeedbackMetadataIterator iter(*this);
  while (iter.HasNext()) {
    FeedbackSlot slot = iter.Next();
    FeedbackSlotKind kind = iter.kind();
    os << "\n Slot " << slot << " " << kind;
  }
  os << "\n";
}

void ClosureFeedbackCellArray::ClosureFeedbackCellArrayPrint(std::ostream& os) {
  PrintHeader(os, "ClosureFeedbackCellArray");
  os << "\n - length: " << length();
  os << "\n - elements:";
  PrintFixedArrayElements<ClosureFeedbackCellArray>(os, this);
  os << "\n";
}

void FeedbackVector::FeedbackVectorPrint(std::ostream& os) {
  PrintHeader(os, "FeedbackVector");
  os << "\n - length: " << length();
  if (length() == 0) {
    os << " (empty)\n";
    return;
  }

  os << "\n - shared function info: " << Brief(shared_function_info());
#ifdef V8_ENABLE_LEAPTIERING
  os << "\n - tiering_in_progress: " << tiering_in_progress();
#else
  os << "\n - tiering state: " << tiering_state();
  if (has_optimized_code()) {
    os << "\n - optimized code: "
       << Brief(optimized_code(GetIsolateForSandbox(*this)));
  } else {
    os << "\n - no optimized code";
  }
  os << "\n - maybe has maglev code: " << maybe_has_maglev_code();
  os << "\n - maybe has turbofan code: " << maybe_has_turbofan_code();
#endif  // !V8_ENABLE_LEAPTIERING
  os << "\n - osr_tiering_in_progress: " << osr_tiering_in_progress();
  os << "\n - invocation count: " << invocation_count();
  os << "\n - closure feedback cell array: ";
  closure_feedback_cell_array()->ClosureFeedbackCellArrayPrint(os);

  FeedbackMetadataIterator iter(metadata());
  while (iter.HasNext()) {
    FeedbackSlot slot = iter.Next();
    FeedbackSlotKind kind = iter.kind();

    os << "\n - slot " << slot << " " << kind << " ";
    FeedbackSlotPrint(os, slot);

    int entry_size = iter.entry_size();
    if (entry_size > 0) os << " {";
    for (int i = 0; i < entry_size; i++) {
      FeedbackSlot slot_with_offset = slot.WithOffset(i);
      os << "\n     [" << slot_with_offset.ToInt()
         << "]: " << Brief(Get(slot_with_offset));
    }
    if (entry_size > 0) os << "\n  }";
  }
  os << "\n";
}

void FeedbackVector::FeedbackSlotPrint(std::ostream& os, FeedbackSlot slot) {
  FeedbackNexus nexus(GetIsolate(), *this, slot);
  nexus.Print(os);
}

void FeedbackNexus::Print(std::ostream& os) {
  auto slot_kind = kind();
  switch (slot_kind) {
    case FeedbackSlotKind::kCall:
    case FeedbackSlotKind::kCloneObject:
    case FeedbackSlotKind::kHasKeyed:
    case FeedbackSlotKind::kInstanceOf:
    case FeedbackSlotKind::kTypeOf:
    case FeedbackSlotKind::kDefineKeyedOwnPropertyInLiteral:
    case FeedbackSlotKind::kStoreInArrayLiteral: {
      os << InlineCacheState2String(ic_state());
      break;
    }
    case FeedbackSlotKind::kLoadGlobalInsideTypeof:
    case FeedbackSlotKind::kLoadGlobalNotInsideTypeof:
    case FeedbackSlotKind::kStoreGlobalSloppy:
    case FeedbackSlotKind::kStoreGlobalStrict: {
      os << InlineCacheState2String(ic_state());
      if (ic_state() == InlineCacheState::MONOMORPHIC) {
        os << "\n   ";
        if (GetFeedback().IsCleared()) {
          // Handler mode: feedback is the cleared value, extra is the handler.
          if (IsLoadGlobalICKind(slot_kind)) {
            LoadHandler::PrintHandler(GetFeedbackExtra().GetHeapObjectOrSmi(),
                                      os);
          } else {
            StoreHandler::PrintHandler(GetFeedbackExtra().GetHeapObjectOrSmi(),
                                       os);
          }
        } else if (IsPropertyCell(GetFeedback().GetHeapObjectOrSmi())) {
          os << Brief(GetFeedback());
        } else {
          // Lexical variable mode: the variable location is encoded in the SMI.
          int handler = GetFeedback().GetHeapObjectOrSmi().ToSmi().value();
          os << (IsLoadGlobalICKind(slot_kind) ? "Load" : "Store");
          os << "Handler(Lexical variable mode)(context ix = "
             << FeedbackNexus::ContextIndexBits::decode(handler)
             << ", slot ix = " << FeedbackNexus::SlotIndexBits::decode(handler)
             << ")";
        }
      }
      break;
    }
    case FeedbackSlotKind::kLoadKeyed:
    case FeedbackSlotKind::kLoadProperty: {
      os << InlineCacheState2String(ic_state());
      if (ic_state() == InlineCacheState::MONOMORPHIC) {
        os << "\n   " << Brief(GetFeedback()) << ": ";
        Tagged<Object> handler = GetFeedbackExtra().GetHeapObjectOrSmi();
        if (IsWeakFixedArray(handler) &&
            !Cast<WeakFixedArray>(handler)->get(0).IsCleared()) {
          handler = Cast<WeakFixedArray>(handler)->get(0).GetHeapObjectOrSmi();
        }
        LoadHandler::PrintHandler(handler, os);
      } else if (ic_state() == InlineCacheState::POLYMORPHIC) {
        Tagged<HeapObject> feedback = GetFeedback().GetHeapObject();
        Tagged<WeakFixedArray> array;
        if (IsName(feedback)) {
          os << " with name " << Brief(feedback);
          array = Cast<WeakFixedArray>(GetFeedbackExtra().GetHeapObject());
        } else {
          array = Cast<WeakFixedArray>(feedback);
        }
        for (int i = 0; i < array->length(); i += 2) {
          os << "\n   " << Brief(array->get(i)) << ": ";
          LoadHandler::PrintHandler(array->get(i + 1).GetHeapObjectOrSmi(), os);
        }
      }
      break;
    }
    case FeedbackSlotKind::kDefineNamedOwn:
    case FeedbackSlotKind::kDefineKeyedOwn:
    case FeedbackSlotKind::kSetNamedSloppy:
    case FeedbackSlotKind::kSetNamedStrict:
    case FeedbackSlotKind::kSetKeyedSloppy:
    case FeedbackSlotKind::kSetKeyedStrict: {
      os << InlineCacheState2String(ic_state());
      if (GetFeedback().IsCleared()) {
        os << "\n   [cleared]";
        break;
      }
      if (ic_state() == InlineCacheState::MONOMORPHIC) {
        Tagged<HeapObject> feedback = GetFeedback().GetHeapObject();
        if (GetFeedbackExtra().IsCleared()) {
          os << " [cleared]\n";
          break;
        }
        if (IsName(feedback)) {
          os << " with name " << Brief(feedback);
          Tagged<WeakFixedArray> array =
              Cast<WeakFixedArray>(GetFeedbackExtra().GetHeapObject());
          os << "\n   " << Brief(array->get(0)) << ": ";
          if (array->get(1).IsCleared()) {
            os << "[cleared]\n";
          } else {
            Tagged<Object> handler = array->get(1).GetHeapObjectOrSmi();
            StoreHandler::PrintHandler(handler, os);
          }
        } else {
          os << "\n   " << Brief(feedback) << ": ";
          StoreHandler::PrintHandler(GetFeedbackExtra().GetHeapObjectOrSmi(),
                                     os);
        }
      } else if (ic_state() == InlineCacheState::POLYMORPHIC) {
        Tagged<HeapObject> feedback = GetFeedback().GetHeapObject();
        Tagged<WeakFixedArray> array;
        if (IsName(feedback)) {
          os << " with name " << Brief(feedback);
          array = Cast<WeakFixedArray>(GetFeedbackExtra().GetHeapObject());
        } else {
          array = Cast<WeakFixedArray>(feedback);
        }
        for (int i = 0; i < array->length(); i += 2) {
          os << "\n   " << Brief(array->get(i)) << ": ";
          if (!array->get(i + 1).IsCleared()) {
            StoreHandler::PrintHandler(array->get(i + 1).GetHeapObjectOrSmi(),
                                       os);
          }
        }
      }
      break;
    }
    case FeedbackSlotKind::kBinaryOp: {
      os << "BinaryOp:" << GetBinaryOperationFeedback();
      break;
    }
    case FeedbackSlotKind::kCompareOp: {
      os << "CompareOp:" << GetCompareOperationFeedback();
      break;
    }
    case FeedbackSlotKind::kForIn: {
      os << "ForIn:" << GetForInFeedback();
      break;
    }
    case FeedbackSlotKind::kLiteral:
      break;
    case FeedbackSlotKind::kJumpLoop:
      os << "JumpLoop";
      break;
    case FeedbackSlotKind::kInvalid:
      UNREACHABLE();
  }
}

void Oddball::OddballPrint(std::ostream& os) {
  PrintHeapObjectHeaderWithoutMap(Tagged<HeapObject>(this), os, "Oddball");
  os << ": ";
  Tagged<String> s = to_string();
  os << s->PrefixForDebugPrint();
  s->PrintUC16(os);
  os << s->SuffixForDebugPrint();
  os << std::endl;
}

void Hole::HolePrint(std::ostream& os) {
  PrintHeapObjectHeaderWithoutMap(*this, os, "Hole");
  ReadOnlyRoots roots = GetReadOnlyRoots();
#define PRINT_SPECIFIC_HOLE(type, name, CamelName) \
  if (*this == roots.name()) {                     \
    os << "\n  <" #name ">";                       \
  }
  HOLE_LIST(PRINT_SPECIFIC_HOLE);
#undef PRINT_SPECIFIC_HOLE

  os << std::endl;
}

void JSAsyncFunctionObject::JSAsyncFunctionObjectPrint(std::ostream& os) {
  JSGeneratorObjectPrint(os);
}

void JSAsyncGeneratorObject::JSAsyncGeneratorObjectPrint(std::ostream& os) {
  JSGeneratorObjectPrint(os);
}

void JSArgumentsObject::JSArgumentsObjectPrint(std::ostream& os) {
  JSObjectPrint(os);
}

void JSStringIterator::JSStringIteratorPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSStringIterator");
  os << "\n - string: " << Brief(string());
  os << "\n - index: " << index();
  JSObjectPrintBody(os, *this);
}

void JSAsyncFromSyncIterator::JSAsyncFromSyncIteratorPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSAsyncFromSyncIterator");
  os << "\n - sync_iterator: " << Brief(sync_iterator());
  os << "\n - next: " << Brief(next());
  JSObjectPrintBody(os, *this);
}

void JSValidIteratorWrapper::JSValidIteratorWrapperPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSValidIteratorWrapper");
  os << "\n - underlying.object: " << Brief(underlying_object());
  os << "\n - underlying.next: " << Brief(underlying_next());
  JSObjectPrintBody(os, *this);
}

void JSPrimitiveWrapper::JSPrimitiveWrapperPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSPrimitiveWrapper");
  os << "\n - value: " << Brief(value());
  JSObjectPrintBody(os, *this);
}

void JSMessageObject::JSMessageObjectPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSMessageObject");
  os << "\n - type: " << static_cast<int>(type());
  os << "\n - arguments: " << Brief(argument());
  os << "\n - script: " << Brief(script());
  os << "\n - stack_trace: " << Brief(stack_trace());
  os << "\n - shared_info: " << Brief(shared_info());
  if (shared_info() == Smi::zero()) {
    os << " (cleared after calculating line ends)";
  } else if (shared_info() == Smi::FromInt(-1)) {
    os << "(no line ends needed)";
  }
  os << "\n - bytecode_offset: " << bytecode_offset();
  os << "\n - start_position: " << start_position();
  os << "\n - end_position: " << end_position();
  os << "\n - error_level: " << error_level();
  JSObjectPrintBody(os, *this);
}

void String::StringPrint(std::ostream& os) {
  PrintHeapObjectHeaderWithoutMap(this, os, "String");
  os << ": ";
  os << PrefixForDebugPrint();
  PrintUC16(os, 0, length());
  os << SuffixForDebugPrint();
}

void Name::NamePrint(std::ostream& os) {
  if (IsString(this)) {
    Cast<String>(this)->StringPrint(os);
  } else {
    os << Brief(this);
  }
}

static const char* const weekdays[] = {"???", "Sun", "Mon", "Tue",
                                       "Wed", "Thu", "Fri", "Sat"};

void JSDate::JSDatePrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSDate");
  os << "\n - value: " << value();
  if (!IsSmi(year())) {
    os << "\n - time = NaN\n";
  } else {
    // TODO(svenpanne) Add some basic formatting to our streams.
    base::ScopedVector<char> buf(100);
    SNPrintF(buf, "\n - time = %s %04d/%02d/%02d %02d:%02d:%02d\n",
             weekdays[IsSmi(weekday()) ? Smi::ToInt(weekday()) + 1 : 0],
             IsSmi(year()) ? Smi::ToInt(year()) : -1,
             IsSmi(month()) ? Smi::ToInt(month()) : -1,
             IsSmi(day()) ? Smi::ToInt(day()) : -1,
             IsSmi(hour()) ? Smi::ToInt(hour()) : -1,
             IsSmi(min()) ? Smi::ToInt(min()) : -1,
             IsSmi(sec()) ? Smi::ToInt(sec()) : -1);
    os << buf.begin();
  }
  JSObjectPrintBody(os, *this);
}

void JSSet::JSSetPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSSet");
  os << "\n - table: " << Brief(table());
  JSObjectPrintBody(os, *this);
}

void JSMap::JSMapPrint(std::ostream& os) {
  JSObjectPrintHeader(os, *this, "JSMap");
  os << "\n - table: " << Brief(table());
  JSObjectPrintBody(os, *this);
}

void JSCollectionIterator::JSCollectionIteratorPrint(std::ostream& os,
                                                     const char* name) {
  JSObjectPrintHeader(os, *this, name);
  os << "\n - table: " << Brief(table());
  os << "\n - index: " << Brief(index());
  JSObjectPrintBody(os, *this);
}

void JSSetIterator::JS
"""


```