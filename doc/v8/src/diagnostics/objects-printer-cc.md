Response:
The user wants to understand the functionality of the C++ source code file `v8/src/diagnostics/objects-printer.cc`.

I need to:
1. **Identify the main purpose of the code**: Based on the file name and content, it seems to be responsible for printing information about V8 objects for debugging and diagnostics.
2. **List the key functionalities**:  Extract the different printing methods for various V8 object types.
3. **Determine if it's a Torque file**: Check if the file extension is `.tq`.
4. **Check for JavaScript relevance and provide an example**: See if the code interacts with concepts visible in JavaScript and illustrate this with a JS example.
5. **Illustrate code logic with input/output examples**: If there are logical steps, create hypothetical input and output scenarios.
6. **Point out common programming errors**: If the code touches on areas prone to user errors, give examples.
7. **Summarize the overall function**:  Provide a concise summary of the file's purpose based on the points above.
这是 V8 源代码文件 `v8/src/diagnostics/objects-printer.cc` 的第一部分，它主要的功能是**提供了一种机制来打印 V8 堆中各种对象的详细信息，用于调试和诊断目的**。

以下是根据提供的代码片段归纳出的功能点：

1. **打印基本对象信息:**
   - 可以打印 `Smi` (小整数) 和 `HeapObject` 的信息。
   - 对于 `Smi`，会打印其十六进制和十进制值。
   - 对于 `HeapObject`，会调用其 `HeapObjectPrint` 方法，该方法会根据对象的具体类型打印更详细的信息。

2. **打印函数回调信息 (`FunctionCallbackInfo`)**:
   -  能够打印传递给 C++ 函数回调的参数信息，例如 `isolate`、`return_value`、`target`、`new_target`、`holder`、`argc` 以及函数调用的 `receiver` 和前几个参数。

3. **打印属性回调信息 (`PropertyCallbackInfo`)**:
   - 能够打印传递给 C++ 属性回调的参数信息，例如 `isolate`、`return_value`、`should_throw`、`holder`、`holderV2`、`data`、`property_key` 和 `receiver`，以及可能的 `value` 参数（用于 setter 调用）。

4. **打印堆对象头部信息:**
   - 提供了打印堆对象头部信息的方法，包括对象的地址、类型（或提供的 ID），以及是否在只读空间。

5. **打印字典内容:**
   - 提供了打印各种字典（例如 `HashTable`、`NameDictionary` 等）内容的方法，遍历字典的键值对并打印。

6. **打印不同类型的堆对象:**
   - 为多种 V8 内部对象类型提供了专门的打印方法 (`...Print`)，例如：
     - 上下文 (`Context`)
     - 哈希表 (`HashTable`, `NameDictionary` 等)
     - 数组 (`FixedArray`)
     - 代码对象 (`Code`, `InstructionStream`)
     - 字符串 (`String`)
     - 函数 (`JSFunction`)
     - 承诺 (`JSPromise`)
     - 正则表达式 (`JSRegExp`)
     - 符号 (`Symbol`)
     - 以及许多其他的 V8 内部对象类型。

7. **处理不同类型的数组元素:**
   - 针对不同类型的数组元素（例如 SMI、普通对象、双精度浮点数、各种类型的 TypedArray）提供了打印方法。

8. **打印 JS 对象属性和元素:**
   - 可以打印 `JSObject` 的属性（包括快属性和慢属性）以及元素。

9. **区分快属性和字典属性:**
   - 在打印 `JSObject` 时，会指示其是否具有快属性（FastProperties）或字典属性（DictionaryProperties）。

10. **打印 Embedder Data:**
    - 能够打印与 V8 对象关联的 Embedder Data。

**关于文件类型和 JavaScript 关联:**

- **文件类型:** `v8/src/diagnostics/objects-printer.cc` 的后缀是 `.cc`，表明它是 **C++ 源代码文件**，而不是 Torque 源代码文件。Torque 文件的后缀是 `.tq`。

- **JavaScript 关联和示例:**  `objects-printer.cc` 的功能直接关联到 JavaScript，因为它负责打印 JavaScript 在 V8 引擎内部表示的对象的信息。例如，当你尝试在 JavaScript 中调试一个对象时，V8 可能会使用类似的功能来输出对象的状态。

   ```javascript
   // JavaScript 示例
   const obj = { a: 1, b: 'hello' };
   const arr = [10, 20, 30];

   // 在 V8 的调试环境中，可能会有命令或 API 调用 objects-printer.cc 中的功能来打印 obj 和 arr 的内部表示。
   // 例如，在 Chrome 开发者工具的 Console 中使用 "console.dir(obj)" 可能会触发类似的内部机制。

   function MyClass(value) {
       this.value = value;
   }
   const myInstance = new MyClass(42);

   // 假设 V8 的调试 API 允许打印内部对象信息：
   // DebugPrint(obj);
   // DebugPrint(arr);
   // DebugPrint(myInstance);
   ```

   在 V8 的内部实现中，`objects-printer.cc` 中的代码会被用来遍历 `obj` 和 `arr` 的内部结构，并打印出它们的属性、值、类型等信息。对于 `myInstance`，它会打印出 `MyClass` 实例的内部字段。

**代码逻辑推理和假设输入/输出:**

假设我们有一个简单的 JavaScript 对象：

```javascript
const myObject = { name: "Alice", age: 30 };
```

当 V8 的调试器调用 `objects-printer.cc` 中的函数来打印 `myObject` 时，可能会有如下的（简化的）输出：

**假设输入:** `myObject` (一个指向 V8 内部 `JSObject` 的指针)

**可能的输出 (简化):**

```
0x...: [JSObject]
 - map: 0x...
 - prototype: 0x...
 - elements: 0x... [PACKED_ELEMENTS]
 - properties: 0x...
 - All own properties (excluding elements): {
    name: "Alice"  (String)
    age: 30  (Smi)
 }
```

这里，输出显示了对象的地址、所属的 `map`、原型、元素（如果存在）、以及名为 `name` 和 `age` 的属性及其对应的值和类型。

**用户常见的编程错误 (与打印功能相关的间接联系):**

虽然 `objects-printer.cc` 本身不直接处理用户的编程错误，但它输出的信息可以帮助诊断这些错误。例如：

1. **类型错误:** 如果一个 JavaScript 操作期望一个数字，但实际得到一个字符串，通过查看对象的内部表示，可以确认变量的类型。
2. **原型链问题:** 通过查看对象的原型链 (`- prototype: ...`)，可以诊断属性查找失败或意外行为的原因。
3. **闭包问题:** 在调试包含闭包的函数时，查看上下文对象 (`Context`) 可以帮助理解变量的作用域和值。
4. **内存泄漏:** 虽然 `objects-printer.cc` 不直接检测内存泄漏，但它可以帮助检查哪些对象仍然存在于堆中，从而辅助泄漏分析。

**总结:**

`v8/src/diagnostics/objects-printer.cc` 的主要功能是为 V8 引擎提供一个强大的对象打印工具，用于在开发和调试过程中检查 V8 堆中各种对象的内部状态。它能够打印基本类型、复杂对象、以及与 JavaScript 执行相关的内部结构信息，是 V8 调试基础设施的关键组成部分。

### 提示词
```
这是目录为v8/src/diagnostics/objects-printer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/diagnostics/objects-printer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
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
    os << "\n   - indices: " << Brief(enum_cache()->ind
```