Response: The user wants me to summarize the functionality of the C++ code snippet provided.
The file path `v8/src/diagnostics/objects-debug.cc` and the numerous include directives suggest that this file is part of the V8 JavaScript engine and deals with debugging and object integrity checks.
The code heavily uses `Verify` methods for different V8 object types, indicating that this file is responsible for validating the state of these objects.
The comments like "Heap Verification Overview" and the use of `#ifdef VERIFY_HEAP` confirm this.

Therefore, the primary function of this code is to implement heap verification for various V8 JavaScript objects. This involves checking the internal consistency and validity of these objects, often recursively checking the validity of their constituent parts.

Regarding the relationship with JavaScript, these verification checks are crucial for ensuring the correct behavior and memory safety of the JavaScript runtime. While the code is in C++, it directly relates to the integrity of JavaScript objects as they are represented within the V8 engine.

To illustrate with JavaScript, consider a simple JavaScript object. The `objects-debug.cc` file contains verification logic that would be applied to the internal C++ representation of this JavaScript object within V8. For instance, if the JavaScript object has properties, the verification code would ensure that these properties are correctly stored and accessible in the underlying C++ structures.

Let's construct a JavaScript example and then describe how the C++ verification code might interact with its internal representation.
这是文件 `v8/src/diagnostics/objects-debug.cc` 的第一部分代码，其主要功能是**实现 V8 引擎中各种对象的堆验证 (Heap Verification)**。

**功能归纳:**

1. **定义了各种 V8 对象的 `Verify` 方法:**  代码中为许多 V8 内部对象类型（例如 `Object`, `HeapObject`, `String`, `JSObject`, `Map`, `FixedArray` 等）定义了 `XXXVerify` 方法。这些方法负责检查特定类型对象的内部状态是否一致且有效。
2. **实现了通用的对象和指针验证:**  `Object::ObjectVerify` 方法是入口，用于判断给定的对象是 Smi 还是 HeapObject，并调用相应的验证方法。  `Object::VerifyPointer` 和 `Object::VerifyAnyTagged` 等方法用于验证对象指针的有效性。
3. **针对特定对象类型进行详细的内部状态检查:**  每个 `XXXVerify` 方法都包含了针对该对象类型特有的验证逻辑，例如：
    * `JSObject::JSObjectVerify`: 检查其属性、元素、map 等是否一致。
    * `Map::MapVerify`: 检查其元信息、描述符、转换等是否正确。
    * `FixedArray::FixedArrayVerify`: 检查其长度和元素指针的有效性。
    * `String::StringVerify`: 检查字符串的长度和内部表示。
4. **支持不同类型的内存区域验证:**  代码中涉及到对堆的不同区域（例如年轻代、老年代、只读空间等）中对象的验证。
5. **使用了宏和模板简化代码:**  例如 `USE_TORQUE_VERIFIER` 宏用于调用 Torque 生成的验证代码。
6. **条件编译:** 使用 `#ifdef VERIFY_HEAP`，表示这些验证代码只在定义了 `VERIFY_HEAP` 宏的情况下编译，通常用于调试和测试版本。

**与 Javascript 的关系 (通过 Javascript 举例说明):**

虽然这段代码是用 C++ 编写的，但它直接关系到 JavaScript 功能的正确性和稳定性。V8 引擎使用这些验证机制来确保在 JavaScript 代码执行过程中，其内部对象的状态不会出现错误或损坏。

例如，考虑以下简单的 Javascript 代码：

```javascript
const obj = { a: 1, b: 'hello' };
const arr = [1, 2, 3];
```

在 V8 引擎内部，`obj` 和 `arr` 会被表示为 C++ 对象。  `objects-debug.cc` 中的验证逻辑就会作用于这些内部表示：

1. **`JSObject::JSObjectVerify` (针对 `obj`)**:
   -  会检查 `obj` 对象的 `map` 指针是否指向有效的 `Map` 对象。
   -  会检查 `obj` 对象的元素（如果有）是否有效。
   -  会遍历 `obj` 的属性 (例如 'a', 'b')，并验证其描述符和值是否正确存储。例如，它会检查属性名是否为字符串，属性值是否为合法的 V8 对象（Smi 或 HeapObject）。对于数值属性 'a: 1'，会检查其内部表示是否为 Smi。对于字符串属性 'b: "hello"'，会检查其内部表示是否为 `SeqString` 或其他字符串类型。

2. **`JSArray::JSArrayVerify` (针对 `arr`)**:
   - 会检查 `arr` 对象的 `map` 指针是否指向 `JSArray` 的 map。
   - 会检查 `arr` 对象的 `elements` 指针是否指向有效的 `FixedArray` 或 `FixedDoubleArray`。
   - 会检查数组的 `length` 属性是否与 `elements` 的长度一致。
   - 会遍历 `elements` 中的元素 (1, 2, 3)，并验证它们是否为合法的 V8 对象 (在本例中是 Smi)。

**更具体的 Javascript 例子和 C++ 验证的对应关系:**

假设我们有以下 Javascript 代码：

```javascript
function foo() {
  return 10;
}
```

在 V8 内部，`foo` 函数会被表示为一个 `JSFunction` 对象。  `JSFunction::JSFunctionVerify` 方法会进行如下检查：

- 检查 `shared_info()` 返回的 `SharedFunctionInfo` 对象是否有效，包含了函数的元数据（例如函数名、参数个数等）。
- 检查 `context()` 返回的 `Context` 对象是否有效，包含了函数的作用域信息。
- 检查 `code()` 返回的 `Code` 对象是否有效，包含了函数编译后的机器码。
- 检查 `raw_feedback_cell()` 返回的 `FeedbackCell` 对象是否有效，用于存储函数的性能分析信息。

**总结:**

`objects-debug.cc` 的第一部分定义了 V8 引擎中对象堆验证的基础架构和核心实现，确保了 JavaScript 运行时的内部数据结构的完整性和一致性。当启用堆验证时，V8 引擎会定期或在特定事件发生时调用这些 `Verify` 方法，以尽早发现潜在的内存错误或逻辑错误，从而提高引擎的可靠性。

### 提示词
```
这是目录为v8/src/diagnostics/objects-debug.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/logging.h"
#include "src/codegen/assembler-inl.h"
#include "src/common/globals.h"
#include "src/date/date.h"
#include "src/diagnostics/disasm.h"
#include "src/diagnostics/disassembler.h"
#include "src/heap/combined-heap.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/heap/read-only-heap.h"
#include "src/ic/handler-configuration-inl.h"
#include "src/init/bootstrapper.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/allocation-site-inl.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/bigint.h"
#include "src/objects/call-site-info-inl.h"
#include "src/objects/cell-inl.h"
#include "src/objects/code-inl.h"
#include "src/objects/data-handler-inl.h"
#include "src/objects/debug-objects-inl.h"
#include "src/objects/elements.h"
#include "src/objects/embedder-data-array-inl.h"
#include "src/objects/embedder-data-slot-inl.h"
#include "src/objects/feedback-cell-inl.h"
#include "src/objects/field-type.h"
#include "src/objects/foreign-inl.h"
#include "src/objects/free-space-inl.h"
#include "src/objects/function-kind.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-atomics-synchronization-inl.h"
#include "src/objects/js-disposable-stack.h"
#include "src/objects/objects-inl.h"
#include "src/objects/objects.h"
#include "src/objects/trusted-object.h"
#include "src/objects/turbofan-types-inl.h"
#include "src/objects/turboshaft-types-inl.h"
#include "src/roots/roots.h"
#ifdef V8_INTL_SUPPORT
#include "src/objects/js-break-iterator-inl.h"
#include "src/objects/js-collator-inl.h"
#endif  // V8_INTL_SUPPORT
#include "src/objects/js-collection-inl.h"
#ifdef V8_INTL_SUPPORT
#include "src/objects/js-date-time-format-inl.h"
#include "src/objects/js-display-names-inl.h"
#include "src/objects/js-duration-format-inl.h"
#endif  // V8_INTL_SUPPORT
#include "src/objects/js-disposable-stack-inl.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/js-iterator-helpers-inl.h"
#ifdef V8_INTL_SUPPORT
#include "src/objects/js-list-format-inl.h"
#include "src/objects/js-locale-inl.h"
#include "src/objects/js-number-format-inl.h"
#include "src/objects/js-plural-rules-inl.h"
#endif  // V8_INTL_SUPPORT
#include "src/objects/js-regexp-inl.h"
#include "src/objects/js-regexp-string-iterator-inl.h"
#include "src/objects/js-shadow-realm-inl.h"
#ifdef V8_INTL_SUPPORT
#include "src/objects/js-relative-time-format-inl.h"
#include "src/objects/js-segment-iterator-inl.h"
#include "src/objects/js-segmenter-inl.h"
#include "src/objects/js-segments-inl.h"
#endif  // V8_INTL_SUPPORT
#include "src/objects/hole-inl.h"
#include "src/objects/js-raw-json-inl.h"
#include "src/objects/js-shared-array-inl.h"
#include "src/objects/js-struct-inl.h"
#include "src/objects/js-temporal-objects-inl.h"
#include "src/objects/js-weak-refs-inl.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/maybe-object.h"
#include "src/objects/megadom-handler-inl.h"
#include "src/objects/microtask-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/oddball-inl.h"
#include "src/objects/promise-inl.h"
#include "src/objects/property-descriptor-object-inl.h"
#include "src/objects/struct-inl.h"
#include "src/objects/swiss-name-dictionary-inl.h"
#include "src/objects/synthetic-module-inl.h"
#include "src/objects/template-objects-inl.h"
#include "src/objects/torque-defined-classes-inl.h"
#include "src/objects/transitions-inl.h"
#include "src/regexp/regexp.h"
#include "src/sandbox/js-dispatch-table-inl.h"
#include "src/utils/ostreams.h"
#include "torque-generated/class-verifiers.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/base/strings.h"
#include "src/debug/debug-wasm-objects-inl.h"
#include "src/wasm/wasm-objects-inl.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

// Heap Verification Overview
// --------------------------
// - Each InstanceType has a separate XXXVerify method which checks an object's
//   integrity in isolation.
// - --verify-heap will iterate over all gc spaces and call ObjectVerify() on
//   every encountered tagged pointer.
// - Verification should be pushed down to the specific instance type if its
//   integrity is independent of an outer object.
// - In cases where the InstanceType is too generic (e.g. FixedArray) the
//   XXXVerify of the outer method has to do recursive verification.
// - If the corresponding objects have inheritence the parent's Verify method
//   is called as well.
// - For any field containing pointes VerifyPointer(...) should be called.
//
// Caveats
// -------
// - Assume that any of the verify methods is incomplete!
// - Some integrity checks are only partially done due to objects being in
//   partially initialized states when a gc happens, for instance when outer
//   objects are allocted before inner ones.
//

#ifdef VERIFY_HEAP

#define USE_TORQUE_VERIFIER(Class)                                \
  void Class::Class##Verify(Isolate* isolate) {                   \
    TorqueGeneratedClassVerifiers::Class##Verify(*this, isolate); \
  }

// static
void Object::ObjectVerify(Tagged<Object> obj, Isolate* isolate) {
  RCS_SCOPE(isolate, RuntimeCallCounterId::kObjectVerify);
  if (IsSmi(obj)) {
    Smi::SmiVerify(Cast<Smi>(obj), isolate);
  } else {
    Cast<HeapObject>(obj)->HeapObjectVerify(isolate);
  }
  PtrComprCageBase cage_base(isolate);
  CHECK(!IsConstructor(obj, cage_base) || IsCallable(obj, cage_base));
}

void Object::VerifyPointer(Isolate* isolate, Tagged<Object> p) {
  if (IsHeapObject(p)) {
    HeapObject::VerifyHeapPointer(isolate, p);
  } else {
    CHECK(IsSmi(p));
  }
}

void Object::VerifyAnyTagged(Isolate* isolate, Tagged<Object> p) {
  if (IsHeapObject(p)) {
    if (V8_EXTERNAL_CODE_SPACE_BOOL) {
      CHECK(IsValidHeapObject(isolate->heap(), Cast<HeapObject>(p)));
    } else {
      HeapObject::VerifyHeapPointer(isolate, p);
    }
  } else {
    CHECK(IsSmi(p));
  }
}

void Object::VerifyMaybeObjectPointer(Isolate* isolate, Tagged<MaybeObject> p) {
  Tagged<HeapObject> heap_object;
  if (p.GetHeapObject(&heap_object)) {
    HeapObject::VerifyHeapPointer(isolate, heap_object);
  } else {
    CHECK(p.IsSmi() || p.IsCleared() || MapWord::IsPacked(p.ptr()));
  }
}

// static
void Smi::SmiVerify(Tagged<Smi> obj, Isolate* isolate) {
  CHECK(IsSmi(obj));
  CHECK(!IsCallable(obj));
  CHECK(!IsConstructor(obj));
}

// static
void TaggedIndex::TaggedIndexVerify(Tagged<TaggedIndex> obj, Isolate* isolate) {
  CHECK(IsTaggedIndex(obj));
}

void HeapObject::HeapObjectVerify(Isolate* isolate) {
  CHECK(IsHeapObject(*this));
  PtrComprCageBase cage_base(isolate);
  Object::VerifyPointer(isolate, map(cage_base));
  CHECK(IsMap(map(cage_base), cage_base));

  CHECK(CheckRequiredAlignment(isolate));

  // Only TrustedObjects live in trusted space. See also TrustedObjectVerify.
  CHECK_IMPLIES(!IsTrustedObject(*this) && !IsFreeSpaceOrFiller(*this),
                !HeapLayout::InTrustedSpace(*this));

  switch (map(cage_base)->instance_type()) {
#define STRING_TYPE_CASE(TYPE, size, name, CamelName) case TYPE:
    STRING_TYPE_LIST(STRING_TYPE_CASE)
#undef STRING_TYPE_CASE
    if (IsConsString(*this, cage_base)) {
      Cast<ConsString>(*this)->ConsStringVerify(isolate);
    } else if (IsSlicedString(*this, cage_base)) {
      Cast<SlicedString>(*this)->SlicedStringVerify(isolate);
    } else if (IsThinString(*this, cage_base)) {
      Cast<ThinString>(*this)->ThinStringVerify(isolate);
    } else if (IsSeqString(*this, cage_base)) {
      Cast<SeqString>(*this)->SeqStringVerify(isolate);
    } else if (IsExternalString(*this, cage_base)) {
      Cast<ExternalString>(*this)->ExternalStringVerify(isolate);
    } else {
      Cast<String>(*this)->StringVerify(isolate);
    }
    break;
    // FixedArray types
    case HASH_TABLE_TYPE:
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
    case ORDERED_NAME_DICTIONARY_TYPE:
    case NAME_TO_INDEX_HASH_TABLE_TYPE:
    case REGISTERED_SYMBOL_TABLE_TYPE:
    case NAME_DICTIONARY_TYPE:
    case GLOBAL_DICTIONARY_TYPE:
    case NUMBER_DICTIONARY_TYPE:
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
    case EPHEMERON_HASH_TABLE_TYPE:
      Cast<FixedArray>(*this)->FixedArrayVerify(isolate);
      break;
    case AWAIT_CONTEXT_TYPE:
    case BLOCK_CONTEXT_TYPE:
    case CATCH_CONTEXT_TYPE:
    case DEBUG_EVALUATE_CONTEXT_TYPE:
    case EVAL_CONTEXT_TYPE:
    case FUNCTION_CONTEXT_TYPE:
    case MODULE_CONTEXT_TYPE:
    case SCRIPT_CONTEXT_TYPE:
    case WITH_CONTEXT_TYPE:
      Cast<Context>(*this)->ContextVerify(isolate);
      break;
    case NATIVE_CONTEXT_TYPE:
      Cast<NativeContext>(*this)->NativeContextVerify(isolate);
      break;
    case FEEDBACK_METADATA_TYPE:
      Cast<FeedbackMetadata>(*this)->FeedbackMetadataVerify(isolate);
      break;
    case TRANSITION_ARRAY_TYPE:
      Cast<TransitionArray>(*this)->TransitionArrayVerify(isolate);
      break;

    case INSTRUCTION_STREAM_TYPE:
      Cast<InstructionStream>(*this)->InstructionStreamVerify(isolate);
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
      Cast<JSObject>(*this)->JSObjectVerify(isolate);
      break;
#if V8_ENABLE_WEBASSEMBLY
    case WASM_TRUSTED_INSTANCE_DATA_TYPE:
      Cast<WasmTrustedInstanceData>(*this)->WasmTrustedInstanceDataVerify(
          isolate);
      break;
    case WASM_DISPATCH_TABLE_TYPE:
      Cast<WasmDispatchTable>(*this)->WasmDispatchTableVerify(isolate);
      break;
    case WASM_VALUE_OBJECT_TYPE:
      Cast<WasmValueObject>(*this)->WasmValueObjectVerify(isolate);
      break;
    case WASM_EXCEPTION_PACKAGE_TYPE:
      Cast<WasmExceptionPackage>(*this)->WasmExceptionPackageVerify(isolate);
      break;
#endif  // V8_ENABLE_WEBASSEMBLY
    case JS_SET_KEY_VALUE_ITERATOR_TYPE:
    case JS_SET_VALUE_ITERATOR_TYPE:
      Cast<JSSetIterator>(*this)->JSSetIteratorVerify(isolate);
      break;
    case JS_MAP_KEY_ITERATOR_TYPE:
    case JS_MAP_KEY_VALUE_ITERATOR_TYPE:
    case JS_MAP_VALUE_ITERATOR_TYPE:
      Cast<JSMapIterator>(*this)->JSMapIteratorVerify(isolate);
      break;
    case FILLER_TYPE:
      break;
    case CODE_TYPE:
      Cast<Code>(*this)->CodeVerify(isolate);
      break;
    case CODE_WRAPPER_TYPE:
      Cast<CodeWrapper>(*this)->CodeWrapperVerify(isolate);
      break;

#define MAKE_TORQUE_CASE(Name, TYPE)          \
  case TYPE:                                  \
    Cast<Name>(*this)->Name##Verify(isolate); \
    break;
      // Every class that has its fields defined in a .tq file and corresponds
      // to exactly one InstanceType value is included in the following list.
      TORQUE_INSTANCE_CHECKERS_SINGLE_FULLY_DEFINED(MAKE_TORQUE_CASE)
      TORQUE_INSTANCE_CHECKERS_MULTIPLE_FULLY_DEFINED(MAKE_TORQUE_CASE)
#undef MAKE_TORQUE_CASE

    case ALLOCATION_SITE_TYPE:
      Cast<AllocationSite>(*this)->AllocationSiteVerify(isolate);
      break;

    case LOAD_HANDLER_TYPE:
      Cast<LoadHandler>(*this)->LoadHandlerVerify(isolate);
      break;

    case STORE_HANDLER_TYPE:
      Cast<StoreHandler>(*this)->StoreHandlerVerify(isolate);
      break;

    case BIG_INT_BASE_TYPE:
      Cast<BigIntBase>(*this)->BigIntBaseVerify(isolate);
      break;

    case JS_CLASS_CONSTRUCTOR_TYPE:
    case JS_PROMISE_CONSTRUCTOR_TYPE:
    case JS_REG_EXP_CONSTRUCTOR_TYPE:
    case JS_ARRAY_CONSTRUCTOR_TYPE:
#define TYPED_ARRAY_CONSTRUCTORS_SWITCH(Type, type, TYPE, Ctype) \
  case TYPE##_TYPED_ARRAY_CONSTRUCTOR_TYPE:
      TYPED_ARRAYS(TYPED_ARRAY_CONSTRUCTORS_SWITCH)
#undef TYPED_ARRAY_CONSTRUCTORS_SWITCH
      Cast<JSFunction>(*this)->JSFunctionVerify(isolate);
      break;
    case JS_LAST_DUMMY_API_OBJECT_TYPE:
      UNREACHABLE();
  }
}

// static
void HeapObject::VerifyHeapPointer(Isolate* isolate, Tagged<Object> p) {
  CHECK(IsHeapObject(p));
  // If you crashed here and {isolate->is_shared()}, there is a bug causing the
  // host of {p} to point to a non-shared object.
  CHECK(IsValidHeapObject(isolate->heap(), Cast<HeapObject>(p)));
  CHECK_IMPLIES(V8_EXTERNAL_CODE_SPACE_BOOL, !IsInstructionStream(p));
}

// static
void HeapObject::VerifyCodePointer(Isolate* isolate, Tagged<Object> p) {
  CHECK(IsHeapObject(p));
  CHECK(IsValidCodeObject(isolate->heap(), Cast<HeapObject>(p)));
  PtrComprCageBase cage_base(isolate);
  CHECK(IsInstructionStream(Cast<HeapObject>(p), cage_base));
}

void Name::NameVerify(Isolate* isolate) {
  PrimitiveHeapObjectVerify(isolate);
  CHECK(IsName(this));
}

void Symbol::SymbolVerify(Isolate* isolate) {
  NameVerify(isolate);
  CHECK(IsSymbol(this));
  uint32_t hash;
  const bool has_hash = TryGetHash(&hash);
  CHECK(has_hash);
  CHECK_GT(hash, 0);
  CHECK(IsUndefined(description(), isolate) || IsString(description()));
  CHECK_IMPLIES(IsPrivateName(), IsPrivate());
  CHECK_IMPLIES(IsPrivateBrand(), IsPrivateName());
}

void BytecodeArray::BytecodeArrayVerify(Isolate* isolate) {
  ExposedTrustedObjectVerify(isolate);

  {
    CHECK(IsSmi(TaggedField<Object>::load(*this, kLengthOffset)));
    CHECK_LE(0, length());
    CHECK_LE(length(), kMaxLength);
  }
  {
    auto o = constant_pool();
    Object::VerifyPointer(isolate, o);
    CHECK(IsTrustedFixedArray(o));
  }
  {
    auto o = handler_table();
    Object::VerifyPointer(isolate, o);
    CHECK(IsTrustedByteArray(o));
  }
  {
    auto o = wrapper();
    Object::VerifyPointer(isolate, o);
    CHECK(IsBytecodeWrapper(o));
    // Our wrapper must point back to us.
    CHECK_EQ(o->bytecode(isolate), *this);
  }
  {
    // Use the raw accessor here as source positions may not be available.
    auto o = raw_source_position_table(kAcquireLoad);
    Object::VerifyPointer(isolate, o);
    CHECK(o == Smi::zero() || IsTrustedByteArray(o));
  }

  // TODO(oth): Walk bytecodes and immediate values to validate sanity.
  // - All bytecodes are known and well formed.
  // - Jumps must go to new instructions starts.
  // - No Illegal bytecodes.
  // - No consecutive sequences of prefix Wide / ExtraWide.
  // - String constants for loads should be internalized strings.
}

void BytecodeWrapper::BytecodeWrapperVerify(Isolate* isolate) {
  if (!this->has_bytecode()) return;
  auto bytecode = this->bytecode(isolate);
  Object::VerifyPointer(isolate, bytecode);
  CHECK_EQ(bytecode->wrapper(), *this);
}

bool JSObject::ElementsAreSafeToExamine(PtrComprCageBase cage_base) const {
  // If a GC was caused while constructing this object, the elements
  // pointer may point to a one pointer filler map.
  return elements(cage_base) !=
         GetReadOnlyRoots(cage_base).one_pointer_filler_map();
}

namespace {

void VerifyJSObjectElements(Isolate* isolate, Tagged<JSObject> object) {
  // Only TypedArrays can have these specialized elements.
  if (IsJSTypedArray(object)) {
    // TODO(bmeurer,v8:4153): Fix CreateTypedArray to either not instantiate
    // the object or propertly initialize it on errors during construction.
    /* CHECK(object->HasTypedArrayOrRabGsabTypedArrayElements()); */
    return;
  }
  CHECK(!IsByteArray(object->elements()));

  if (object->HasDoubleElements()) {
    if (object->elements()->length() > 0) {
      CHECK(IsFixedDoubleArray(object->elements()));
    }
    return;
  }

  if (object->HasSloppyArgumentsElements()) {
    CHECK(IsSloppyArgumentsElements(object->elements()));
    return;
  }

  Tagged<FixedArray> elements = Cast<FixedArray>(object->elements());
  if (object->HasSmiElements()) {
    // We might have a partially initialized backing store, in which case we
    // allow the hole + smi values.
    for (int i = 0; i < elements->length(); i++) {
      Tagged<Object> value = elements->get(i);
      CHECK(IsSmi(value) || IsTheHole(value, isolate));
    }
  } else if (object->HasObjectElements()) {
    for (int i = 0; i < elements->length(); i++) {
      Tagged<Object> element = elements->get(i);
      CHECK(!HasWeakHeapObjectTag(element));
    }
  }
}
}  // namespace

void JSObject::JSObjectVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSObjectVerify(*this, isolate);
  VerifyHeapPointer(isolate, elements());

  CHECK_IMPLIES(HasSloppyArgumentsElements(), IsJSArgumentsObject(*this));
  if (HasFastProperties()) {
    int actual_unused_property_fields = map()->GetInObjectProperties() +
                                        property_array()->length() -
                                        map()->NextFreePropertyIndex();
    if (map()->UnusedPropertyFields() != actual_unused_property_fields) {
      // There are two reasons why this can happen:
      // - in the middle of StoreTransitionStub when the new extended backing
      //   store is already set into the object and the allocation of the
      //   HeapNumber triggers GC while the map isn't updated yet.
      // - deletion of the last property can leave additional backing store
      //   capacity behind.
      CHECK_GT(actual_unused_property_fields, map()->UnusedPropertyFields());
      int delta = actual_unused_property_fields - map()->UnusedPropertyFields();
      CHECK_EQ(0, delta % JSObject::kFieldsAdded);
    }
    Tagged<DescriptorArray> descriptors = map()->instance_descriptors(isolate);
    bool is_transitionable_fast_elements_kind =
        IsTransitionableFastElementsKind(map()->elements_kind());

    for (InternalIndex i : map()->IterateOwnDescriptors()) {
      PropertyDetails details = descriptors->GetDetails(i);
      if (details.location() == PropertyLocation::kField) {
        CHECK_EQ(PropertyKind::kData, details.kind());
        Representation r = details.representation();
        FieldIndex index = FieldIndex::ForDetails(map(), details);
        if (COMPRESS_POINTERS_BOOL && index.is_inobject()) {
          VerifyObjectField(isolate, index.offset());
        }
        Tagged<Object> value = RawFastPropertyAt(index);
        CHECK_IMPLIES(r.IsDouble(), IsHeapNumber(value));
        if (IsUninitialized(value, isolate)) continue;
        CHECK_IMPLIES(r.IsSmi(), IsSmi(value));
        CHECK_IMPLIES(r.IsHeapObject(), IsHeapObject(value));
        Tagged<FieldType> field_type = descriptors->GetFieldType(i);
        bool type_is_none = IsNone(field_type);
        bool type_is_any = IsAny(field_type);
        if (r.IsNone()) {
          CHECK(type_is_none);
        } else if (r.IsHeapObject()) {
          CHECK(!type_is_none);
          if (!type_is_any) {
            CHECK_IMPLIES(FieldType::NowStable(field_type),
                          map()->is_deprecated() ||
                              FieldType::NowContains(field_type, value));
          }
        } else {
          CHECK(type_is_any);
        }
        CHECK_IMPLIES(is_transitionable_fast_elements_kind,
                      Map::IsMostGeneralFieldType(r, field_type));
      }
    }

    if (map()->EnumLength() != kInvalidEnumCacheSentinel) {
      Tagged<EnumCache> enum_cache = descriptors->enum_cache();
      Tagged<FixedArray> keys = enum_cache->keys();
      Tagged<FixedArray> indices = enum_cache->indices();
      CHECK_LE(map()->EnumLength(), keys->length());
      CHECK_IMPLIES(indices != ReadOnlyRoots(isolate).empty_fixed_array(),
                    keys->length() == indices->length());
    }
  }

  // If a GC was caused while constructing this object, the elements
  // pointer may point to a one pointer filler map.
  if (ElementsAreSafeToExamine(isolate)) {
    CHECK_EQ((map()->has_fast_smi_or_object_elements() ||
              map()->has_any_nonextensible_elements() ||
              (elements() == GetReadOnlyRoots().empty_fixed_array()) ||
              HasFastStringWrapperElements()),
             (elements()->map() == GetReadOnlyRoots().fixed_array_map() ||
              elements()->map() == GetReadOnlyRoots().fixed_cow_array_map()));
    CHECK_EQ(map()->has_fast_object_elements(), HasObjectElements());
    VerifyJSObjectElements(isolate, *this);
  }
}

void Map::MapVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::MapVerify(*this, isolate);
  Heap* heap = isolate->heap();
  CHECK(!HeapLayout::InYoungGeneration(Tagged<Map>(*this)));
  CHECK(FIRST_TYPE <= instance_type() && instance_type() <= LAST_TYPE);
  CHECK(instance_size() == kVariableSizeSentinel ||
        (kTaggedSize <= instance_size() &&
         static_cast<size_t>(instance_size()) < heap->Capacity()));
  if (IsContextMap(*this)) {
    // The map for the NativeContext is allocated before the NativeContext
    // itself, so it may happen that during a GC the native_context() is still
    // null.
    CHECK(IsNull(native_context_or_null()) ||
          IsNativeContext(native_context_or_null()));
    // The context's meta map is tied to the same native context.
    CHECK_EQ(native_context_or_null(), map()->native_context_or_null());
  } else {
    if (IsUndefined(GetBackPointer(), isolate)) {
      // Root maps must not have descriptors in the descriptor array that do not
      // belong to the map.
      CHECK_EQ(NumberOfOwnDescriptors(),
               instance_descriptors(isolate)->number_of_descriptors());
    } else {
      // If there is a parent map it must be non-stable.
      Tagged<Map> parent = Cast<Map>(GetBackPointer());
      CHECK(!parent->is_stable());
      Tagged<DescriptorArray> descriptors = instance_descriptors(isolate);
      if (!is_deprecated() && !parent->is_deprecated()) {
        CHECK_EQ(IsInobjectSlackTrackingInProgress(),
                 parent->IsInobjectSlackTrackingInProgress());
      }
      if (descriptors == parent->instance_descriptors(isolate)) {
        if (NumberOfOwnDescriptors() == parent->NumberOfOwnDescriptors() + 1) {
          // Descriptors sharing through property transitions takes over
          // ownership from the parent map.
          CHECK(!parent->owns_descriptors());
        } else {
          CHECK_EQ(NumberOfOwnDescriptors(), parent->NumberOfOwnDescriptors());
          // Descriptors sharing through special transitions properly takes over
          // ownership from the parent map unless it uses the canonical empty
          // descriptor array.
          if (descriptors != ReadOnlyRoots(isolate).empty_descriptor_array()) {
            CHECK_IMPLIES(owns_descriptors(), !parent->owns_descriptors());
            CHECK_IMPLIES(parent->owns_descriptors(), !owns_descriptors());
          }
        }
      }
    }
  }
  SLOW_DCHECK(instance_descriptors(isolate)->IsSortedNoDuplicates());
  SLOW_DCHECK(TransitionsAccessor(isolate, *this).IsSortedNoDuplicates());
  SLOW_DCHECK(
      TransitionsAccessor(isolate, *this).IsConsistentWithBackPointers());
  // Only JSFunction maps have has_prototype_slot() bit set and constructible
  // JSFunction objects must have prototype slot.
  CHECK_IMPLIES(has_prototype_slot(), IsJSFunctionMap(*this));

  if (InstanceTypeChecker::IsNativeContextSpecific(instance_type())) {
    // Native context-specific objects must have their own contextful meta map
    // modulo the following exceptions.
    if (instance_type() == NATIVE_CONTEXT_TYPE ||
        instance_type() == JS_GLOBAL_PROXY_TYPE) {
      // 1) Diring creation of the NativeContext the native context field might
      //    be not be initialized yet.
      // 2) The same applies to the placeholder JSGlobalProxy object created by
      //    Factory::NewUninitializedJSGlobalProxy.
      CHECK(IsNull(map()->native_context_or_null()) ||
            IsNativeContext(map()->native_context_or_null()));

    } else if (instance_type() == JS_SPECIAL_API_OBJECT_TYPE) {
      // 3) Remote Api objects' maps have the RO meta map (and thus are not
      //    tied to any native context) while all the other Api objects are
      //    tied to a native context.
      CHECK_IMPLIES(map() != GetReadOnlyRoots().meta_map(),
                    IsNativeContext(map()->native_context_or_null()));

    } else {
      // For all the other objects native context specific objects the
      // native context field must already be initialized.
      CHECK(IsNativeContext(map()->native_context_or_null()));
    }
  } else if (InstanceTypeChecker::IsAlwaysSharedSpaceJSObject(
                 instance_type())) {
    // Shared objects' maps must use the RO meta map.
    CHECK_EQ(map(), GetReadOnlyRoots().meta_map());
  }

  if (IsJSObjectMap(*this)) {
    int header_end_offset = JSObject::GetHeaderSize(*this);
    int inobject_fields_start_offset = GetInObjectPropertyOffset(0);
    // Ensure that embedder fields are located exactly between header and
    // inobject properties.
    CHECK_EQ(header_end_offset, JSObject::GetEmbedderFieldsStartOffset(*this));
    CHECK_EQ(header_end_offset +
                 JSObject::GetEmbedderFieldCount(*this) * kEmbedderDataSlotSize,
             inobject_fields_start_offset);

    if (IsJSSharedStructMap(*this) || IsJSSharedArrayMap(*this) ||
        IsJSAtomicsMutex(*this) || IsJSAtomicsCondition(*this)) {
      if (COMPRESS_POINTERS_IN_MULTIPLE_CAGES_BOOL) {
        // TODO(v8:14089): Verify what should be checked in this configuration
        // and again merge with the else-branch below.
        // CHECK(InSharedHeap());
        CHECK(IsUndefined(GetBackPointer(), isolate));
        // Object maybe_cell = prototype_validity_cell(kRelaxedLoad);
        // if (maybe_cell.IsCell()) CHECK(maybe_cell.InSharedHeap());
        CHECK(!is_extensible());
        CHECK(!is_prototype_map());
        CHECK(OnlyHasSimpleProperties());
        // CHECK(instance_descriptors(isolate).InSharedHeap());
        if (IsJSSharedArrayMap(*this)) {
          CHECK(has_shared_array_elements());
        }
      } else {
        CHECK(HeapLayout::InAnySharedSpace(*this));
        CHECK(IsUndefined(GetBackPointer(), isolate));
        Tagged<Object> maybe_cell = prototype_validity_cell(kRelaxedLoad);
        if (IsCell(maybe_cell))
          CHECK(HeapLayout::InAnySharedSpace(Cast<Cell>(maybe_cell)));
        CHECK(!is_extensible());
        CHECK(!is_prototype_map());
        CHECK(OnlyHasSimpleProperties());
        CHECK(HeapLayout::InAnySharedSpace(instance_descriptors(isolate)));
        if (IsJSSharedArrayMap(*this)) {
          CHECK(has_shared_array_elements());
        }
      }
    }

    // Check constuctor value in JSFunction's maps.
    if (IsJSFunctionMap(*this) && !IsMap(constructor_or_back_pointer())) {
      Tagged<Object> maybe_constructor = constructor_or_back_pointer();
      // Constructor field might still contain a tuple if this map used to
      // have non-instance prototype earlier.
      CHECK_IMPLIES(has_non_instance_prototype(), IsTuple2(maybe_constructor));
      if (IsTuple2(maybe_constructor)) {
        Tagged<Tuple2> tuple = Cast<Tuple2>(maybe_constructor);
        // Unwrap the {constructor, non-instance_prototype} pair.
        maybe_constructor = tuple->value1();
        CHECK(!IsJSReceiver(tuple->value2()));
      }
      CHECK(IsJSFunction(maybe_constructor) ||
            IsFunctionTemplateInfo(maybe_constructor) ||
            // The above check might fail until empty function setup is done.
            IsUndefined(isolate->raw_native_context()->get(
                Context::EMPTY_FUNCTION_INDEX)));
    }
  }

  if (!may_have_interesting_properties()) {
    CHECK(!has_named_interceptor());
    CHECK(!is_dictionary_map());
    CHECK(!is_access_check_needed());
    Tagged<DescriptorArray> const descriptors = instance_descriptors(isolate);
    for (InternalIndex i : IterateOwnDescriptors()) {
      CHECK(!descriptors->GetKey(i)->IsInteresting(isolate));
    }
  }
  CHECK_IMPLIES(has_named_interceptor(), may_have_interesting_properties());
  CHECK_IMPLIES(is_dictionary_map(), may_have_interesting_properties());
  CHECK_IMPLIES(is_dictionary_map(), owns_descriptors());
  CHECK_IMPLIES(is_access_check_needed(), may_have_interesting_properties());
  CHECK_IMPLIES(
      IsJSObjectMap(*this) && !CanHaveFastTransitionableElementsKind(),
      IsDictionaryElementsKind(elements_kind()) ||
          IsTerminalElementsKind(elements_kind()) ||
          IsAnyHoleyNonextensibleElementsKind(elements_kind()) ||
          IsSharedArrayElementsKind(elements_kind()));
  CHECK_IMPLIES(is_deprecated(), !is_stable());
  if (is_prototype_map()) {
    CHECK(prototype_info() == Smi::zero() || IsPrototypeInfo(prototype_info()));
  }
}

void Map::DictionaryMapVerify(Isolate* isolate) {
  MapVerify(isolate);
  CHECK(is_dictionary_map());
  CHECK_EQ(kInvalidEnumCacheSentinel, EnumLength());
  CHECK_EQ(ReadOnlyRoots(isolate).empty_descriptor_array(),
           instance_descriptors(isolate));
  CHECK_EQ(0, UnusedPropertyFields());
  CHECK_EQ(Map::GetVisitorId(*this), visitor_id());
}

void EmbedderDataArray::EmbedderDataArrayVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::EmbedderDataArrayVerify(*this, isolate);
  EmbedderDataSlot start(*this, 0);
  EmbedderDataSlot end(*this, length());
  for (EmbedderDataSlot slot = start; slot < end; ++slot) {
    Tagged<Object> e = slot.load_tagged();
    Object::VerifyPointer(isolate, e);
  }
}

void FixedArrayBase::FixedArrayBaseVerify(Isolate* isolate) {
  CHECK(IsSmi(length_.load()));
}

void FixedArray::FixedArrayVerify(Isolate* isolate) {
  CHECK(IsSmi(length_.load()));

  for (int i = 0; i < length(); ++i) {
    Object::VerifyPointer(isolate, get(i));
  }

  if (this == ReadOnlyRoots(isolate).empty_fixed_array()) {
    CHECK_EQ(length(), 0);
    CHECK_EQ(map(), ReadOnlyRoots(isolate).fixed_array_map());
  }
}

void TrustedFixedArray::TrustedFixedArrayVerify(Isolate* isolate) {
  TrustedObjectVerify(isolate);
  CHECK(IsSmi(length_.load()));

  for (int i = 0; i < length(); ++i) {
    Object::VerifyPointer(isolate, get(i));
  }
}

void ProtectedFixedArray::ProtectedFixedArrayVerify(Isolate* isolate) {
  TrustedObjectVerify(isolate);

  CHECK(IsSmi(length_.load()));

  for (int i = 0; i < length(); ++i) {
    Tagged<Object> element = get(i);
    CHECK(IsSmi(element) || IsTrustedObject(element));
    Object::VerifyPointer(isolate, element);
  }
}

void RegExpMatchInfo::RegExpMatchInfoVerify(Isolate* isolate) {
  CHECK(IsSmi(length_.load()));
  CHECK_GE(capacity(), kMinCapacity);
  CHECK_LE(capacity(), kMaxCapacity);
  CHECK_GE(number_of_capture_registers(), kMinCapacity);
  CHECK_LE(number_of_capture_registers(), capacity());
  CHECK(IsString(last_subject()));
  Object::VerifyPointer(isolate, last_input());
  for (int i = 0; i < capacity(); ++i) {
    CHECK(IsSmi(get(i)));
  }
}

void FeedbackCell::FeedbackCellVerify(Isolate* isolate) {
  Tagged<Object> v = value();
  Object::VerifyPointer(isolate, v);
  CHECK(IsUndefined(v) || IsClosureFeedbackCellArray(v) || IsFeedbackVector(v));

#ifdef V8_ENABLE_LEAPTIERING
  JSDispatchHandle handle = dispatch_handle();
  if (handle == kNullJSDispatchHandle) return;

  JSDispatchTable* jdt = GetProcessWideJSDispatchTable();
  Tagged<Code> code = jdt->GetCode(handle);
  CodeKind kind = code->kind();
  CHECK(kind == CodeKind::FOR_TESTING || kind == CodeKind::BUILTIN ||
        kind == CodeKind::INTERPRETED_FUNCTION || kind == CodeKind::BASELINE ||
        kind == CodeKind::MAGLEV || kind == CodeKind::TURBOFAN_JS);
#endif
}

void ClosureFeedbackCellArray::ClosureFeedbackCellArrayVerify(
    Isolate* isolate) {
  CHECK(IsSmi(length_.load()));
  for (int i = 0; i < length(); ++i) {
    Object::VerifyPointer(isolate, get(i));
  }
}

void WeakFixedArray::WeakFixedArrayVerify(Isolate* isolate) {
  CHECK(IsSmi(length_.load()));
  for (int i = 0; i < length(); i++) {
    Object::VerifyMaybeObjectPointer(isolate, get(i));
  }
}

void TrustedWeakFixedArray::TrustedWeakFixedArrayVerify(Isolate* isolate) {
  CHECK(IsSmi(length_.load()));
  for (int i = 0; i < length(); i++) {
    Object::VerifyMaybeObjectPointer(isolate, get(i));
  }
}

void ScriptContextTable::ScriptContextTableVerify(Isolate* isolate) {
  CHECK(IsSmi(capacity_.load()));
  CHECK(IsSmi(length_.load()));
  int len = length(kAcquireLoad);
  CHECK_LE(0, len);
  CHECK_LE(len, capacity());
  CHECK(IsNameToIndexHashTable(names_to_context_index()));
  for (int i = 0; i < len; ++i) {
    Tagged<Context> o = get(i);
    Object::VerifyPointer(isolate, o);
    CHECK(IsContext(o));
    CHECK(o->IsScriptContext());
  }
}

void ArrayList::ArrayListVerify(Isolate* isolate) {
  CHECK_LE(0, length());
  CHECK_LE(length(), capacity());
  CHECK_IMPLIES(capacity() == 0,
                this == ReadOnlyRoots(isolate).empty_array_list());
  for (int i = 0; i < capacity(); ++i) {
    Object::VerifyPointer(isolate, get(i));
  }
}

void PropertyArray::PropertyArrayVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::PropertyArrayVerify(*this, isolate);
  if (length() == 0) {
    CHECK_EQ(*this, ReadOnlyRoots(isolate).empty_property_array());
    return;
  }
  // There are no empty PropertyArrays.
  CHECK_LT(0, length());
  for (int i = 0; i < length(); i++) {
    Tagged<Object> e = get(i);
    Object::VerifyPointer(isolate, e);
  }
}

void ByteArray::ByteArrayVerify(Isolate* isolate) {}

void TrustedByteArray::TrustedByteArrayVerify(Isolate* isolate) {
  TrustedObjectVerify(isolate);
}

void FixedDoubleArray::FixedDoubleArrayVerify(Isolate* isolate) {
  for (int i = 0; i < length(); i++) {
    if (!is_the_hole(i)) {
      uint64_t value = get_representation(i);
      uint64_t unexpected =
          base::bit_cast<uint64_t>(std::numeric_limits<double>::quiet_NaN()) &
          uint64_t{0x7FF8000000000000};
      // Create implementation specific sNaN by inverting relevant bit.
      unexpected ^= uint64_t{0x0008000000000000};
      CHECK((value & uint64_t{0x7FF8000000000000}) != unexpected ||
            (value & uint64_t{0x0007FFFFFFFFFFFF}) == uint64_t{0});
    }
  }
}

void Context::ContextVerify(Isolate* isolate) {
  if (has_extension()) VerifyExtensionSlot(extension());
  TorqueGeneratedClassVerifiers::ContextVerify(*this, isolate);
  for (int i = 0; i < length(); i++) {
    VerifyObjectField(isolate, OffsetOfElementAt(i));
  }
  if (IsScriptContext()) {
    Tagged<Object> side_data = get(CONTEXT_SIDE_TABLE_PROPERTY_INDEX);
    CHECK(IsFixedArray(side_data));
    Tagged<FixedArray> side_data_array = Cast<FixedArray>(side_data);
    if (v8_flags.const_tracking_let) {
      for (int i = 0; i < side_data_array->length(); i++) {
        Tagged<Object> element = side_data_array->get(i);
        if (IsSmi(element)) {
          int value = element.ToSmi().value();
          CHECK(ContextSidePropertyCell::kOther <= value);
          CHECK(value <= ContextSidePropertyCell::kMutableHeapNumber);
        } else {
          // The slot contains `undefined` before the variable is initialized.
          CHECK(IsUndefined(element) || IsContextSidePropertyCell(element));
        }
      }
    } else {
      CHECK_EQ(0, side_data_array->length());
    }
  }
}

void NativeContext::NativeContextVerify(Isolate* isolate) {
  ContextVerify(isolate);
  CHECK(retained_maps() == Smi::zero() || IsWeakArrayList(retained_maps()));
  CHECK_EQ(length(), NativeContext::NATIVE_CONTEXT_SLOTS);
  CHECK_EQ(kVariableSizeSentinel, map()->instance_size());
}

void FeedbackMetadata::FeedbackMetadataVerify(Isolate* isolate) {
  if (slot_count() == 0 && create_closure_slot_count() == 0) {
    CHECK_EQ(ReadOnlyRoots(isolate).empty_feedback_metadata(), *this);
  } else {
    FeedbackMetadataIterator iter(*this);
    while (iter.HasNext()) {
      iter.Next();
      FeedbackSlotKind kind = iter.kind();
      CHECK_NE(FeedbackSlotKind::kInvalid, kind);
      CHECK_GT(kFeedbackSlotKindCount, kind);
    }
  }
}

void DescriptorArray::DescriptorArrayVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::DescriptorArrayVerify(*this, isolate);
  if (number_of_all_descriptors() == 0) {
    CHECK_EQ(ReadOnlyRoots(isolate).empty_descriptor_array(), *this);
    CHECK_EQ(0, number_of_all_descriptors());
    CHECK_EQ(0, number_of_descriptors());
    CHECK_EQ(ReadOnlyRoots(isolate).empty_enum_cache(), enum_cache());
  } else {
    CHECK_LT(0, number_of_all_descriptors());
    CHECK_LE(number_of_descriptors(), number_of_all_descriptors());

    // Check that properties with private symbols names are non-enumerable, and
    // that fields are in order.
    int expected_field_index = 0;
    for (InternalIndex descriptor :
         InternalIndex::Range(number_of_descriptors())) {
      Tagged<Object> key =
          *(GetDescriptorSlot(descriptor.as_int()) + kEntryKeyIndex);
      // number_of_descriptors() may be out of sync with the actual descriptors
      // written during descriptor array construction.
      if (IsUndefined(key, isolate)) continue;
      PropertyDetails details = GetDetails(descriptor);
      if (Cast<Name>(key)->IsPrivate()) {
        CHECK_NE(details.attributes() & DONT_ENUM, 0);
      }
      Tagged<MaybeObject> value = GetValue(descriptor);
      if (details.location() == PropertyLocation::kField) {
        CHECK_EQ(details.field_index(), expected_field_index);
        CHECK(value == FieldType::None() || value == FieldType::Any() ||
              IsMap(value.GetHeapObjectAssumeWeak()));
        expected_field_index += details.field_width_in_words();
      } else {
        CHECK(!value.IsWeakOrCleared());
        CHECK(!IsMap(Cast<Object>(value)));
      }
    }
  }
}

void TransitionArray::TransitionArrayVerify(Isolate* isolate) {
  WeakFixedArrayVerify(isolate);
  CHECK_LE(LengthFor(number_of_transitions()), length());

  ReadOnlyRoots roots(isolate);
  Tagged<Map> owner;

  // Check all entries have the same owner
  for (int i = 0; i < number_of_transitions(); ++i) {
    Tagged<Map> target = GetTarget(i);
    Tagged<Map> parent = Cast<Map>(target->constructor_or_back_pointer());
    if (owner.is_null()) {
      parent = owner;
    } else {
      CHECK_EQ(parent, owner);
    }
  }
  // Check all entries have the same owner
  if (HasPrototypeTransitions()) {
    Tagged<WeakFixedArray> proto_trans = GetPrototypeTransitions();
    int length = TransitionArray::NumberOfPrototypeTransitions(proto_trans);
    for (int i = 0; i < length; ++i) {
      int index = TransitionArray::kProtoTransitionHeaderSize + i;
      Tagged<MaybeObject> maybe_target = proto_trans->get(index);
      Tagged<HeapObject> target;
      if (maybe_target.GetHeapObjectIfWeak(&target)) {
        if (v8_flags.move_prototype_transitions_first) {
          Tagged<Map> parent =
              Cast<Map>(Cast<Map>(target)->constructor_or_back_pointer());
          if (owner.is_null()) {
            parent = Cast<Map>(target);
          } else {
            CHECK_EQ(parent, owner);
          }
        } else {
          CHECK(IsUndefined(Cast<Map>(target)->GetBackPointer()));
        }
      }
    }
  }
  // Check all entries are valid
  if (HasSideStepTransitions()) {
    Tagged<WeakFixedArray> side_trans = GetSideStepTransitions();
    for (uint32_t index = SideStepTransition::kFirstMapIdx;
         index <= SideStepTransition::kLastMapIdx; ++index) {
      Tagged<MaybeObject> maybe_target = side_trans->get(index);
      Tagged<HeapObject> target;
      if (maybe_target.GetHeapObjectIfWeak(&target)) {
        CHECK(IsMap(target));
        if (!owner.is_null()) {
          CHECK_EQ(target->map(), owner->map());
        }
      } else {
        CHECK(maybe_target == SideStepTransition::Unreachable ||
              maybe_target == SideStepTransition::Empty ||
              maybe_target.IsCleared());
      }
    }
    Tagged<MaybeObject> maybe_cell =
        side_trans->get(SideStepTransition::index_of(
            SideStepTransition::Kind::kObjectAssignValidityCell));
    Tagged<HeapObject> cell;
    if (maybe_cell.GetHeapObjectIfWeak(&cell)) {
      CHECK(IsCell(cell));
    } else {
      CHECK(maybe_cell == SideStepTransition::Empty || maybe_cell.IsCleared());
    }
  }
}

namespace {
void SloppyArgumentsElementsVerify(Isolate* isolate,
                                   Tagged<SloppyArgumentsElements> elements,
                                   Tagged<JSObject> holder) {
  elements->SloppyArgumentsElementsVerify(isolate);
  ElementsKind kind = holder->GetElementsKind();
  bool is_fast = kind == FAST_SLOPPY_ARGUMENTS_ELEMENTS;
  Tagged<Context> context_object = elements->context();
  Tagged<FixedArray> arg_elements = elements->arguments();
  if (arg_elements->length() == 0) {
    CHECK(arg_elements == ReadOnlyRoots(isolate).empty_fixed_array());
    return;
  }
  ElementsAccessor* accessor;
  if (is_fast) {
    accessor = ElementsAccessor::ForKind(HOLEY_ELEMENTS);
  } else {
    accessor = ElementsAccessor::ForKind(DICTIONARY_ELEMENTS);
  }
  int nofMappedParameters = 0;
  int maxMappedIndex = 0;
  for (int i = 0; i < nofMappedParameters; i++) {
    // Verify that each context-mapped argument is either the hole or a valid
    // Smi within context length range.
    Tagged<Object> mapped = elements->mapped_entries(i, kRelaxedLoad);
    if (IsTheHole(mapped, isolate)) {
      // Slow sloppy arguments can be holey.
      if (!is_fast) continue;
      // Fast sloppy arguments elements are never holey. Either the element is
      // context-mapped or present in the arguments elements.
      CHECK(accessor->HasElement(holder, i, arg_elements));
      continue;
    }
    int mappedIndex = Smi::ToInt(mapped);
    nofMappedParameters++;
    CHECK_LE(maxMappedIndex, mappedIndex);
    maxMappedIndex = mappedIndex;
    Tagged<Object> value = context_object->get(mappedIndex);
    CHECK(IsObject(value));
    // None of the context-mapped entries should exist in the arguments
    // elements.
    CHECK(!accessor->HasElement(holder, i, arg_elements));
  }
  CHECK_LE(nofMappedParameters, context_object->length());
  CHECK_LE(nofMappedParameters, arg_elements->length());
  CHECK_LE(maxMappedIndex, context_object->length());
  CHECK_LE(maxMappedIndex, arg_elements->length());
}
}  // namespace

void JSArgumentsObject::JSArgumentsObjectVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSArgumentsObjectVerify(*this, isolate);
  if (IsSloppyArgumentsElementsKind(GetElementsKind())) {
    SloppyArgumentsElementsVerify(
        isolate, Cast<SloppyArgumentsElements>(elements()), *this);
  }
  Tagged<NativeContext> native_context = map()->map()->native_context();
  if (map() == native_context->get(Context::SLOPPY_ARGUMENTS_MAP_INDEX) ||
      map() == native_context->get(Context::SLOW_ALIASED_ARGUMENTS_MAP_INDEX) ||
      map() == native_context->get(Context::FAST_ALIASED_ARGUMENTS_MAP_INDEX)) {
    VerifyObjectField(isolate, JSSloppyArgumentsObject::kLengthOffset);
    VerifyObjectField(isolate, JSSloppyArgumentsObject::kCalleeOffset);
  } else if (map() ==
             native_context->get(Context::STRICT_ARGUMENTS_MAP_INDEX)) {
    VerifyObjectField(isolate, JSStrictArgumentsObject::kLengthOffset);
  }
}

void JSAsyncFunctionObject::JSAsyncFunctionObjectVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSAsyncFunctionObjectVerify(*this, isolate);
}

void JSAsyncGeneratorObject::JSAsyncGeneratorObjectVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSAsyncGeneratorObjectVerify(*this, isolate);
}

void JSDate::JSDateVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSDateVerify(*this, isolate);

  if (IsSmi(month())) {
    int month = Smi::ToInt(this->month());
    CHECK(0 <= month && month <= 11);
  }
  if (IsSmi(day())) {
    int day = Smi::ToInt(this->day());
    CHECK(1 <= day && day <= 31);
  }
  if (IsSmi(hour())) {
    int hour = Smi::ToInt(this->hour());
    CHECK(0 <= hour && hour <= 23);
  }
  if (IsSmi(min())) {
    int min = Smi::ToInt(this->min());
    CHECK(0 <= min && min <= 59);
  }
  if (IsSmi(sec())) {
    int sec = Smi::ToInt(this->sec());
    CHECK(0 <= sec && sec <= 59);
  }
  if (IsSmi(weekday())) {
    int weekday = Smi::ToInt(this->weekday());
    CHECK(0 <= weekday && weekday <= 6);
  }
  if (IsSmi(cache_stamp())) {
    CHECK(Smi::ToInt(cache_stamp()) <=
          Smi::ToInt(isolate->date_cache()->stamp()));
  }
}

void String::StringVerify(Isolate* isolate) {
  PrimitiveHeapObjectVerify(isolate);
  CHECK(IsString(this, isolate));
  CHECK(length() >= 0 && length() <= Smi::kMaxValue);
  CHECK_IMPLIES(length() == 0, this == ReadOnlyRoots(isolate).empty_string());
  if (IsInternalizedString(this)) {
    CHECK(HasHashCode());
    CHECK(!HeapLayout::InYoungGeneration(this));
  }
}

void ConsString::ConsStringVerify(Isolate* isolate) {
  StringVerify(isolate);
  CHECK(IsConsString(this, isolate));
  CHECK_GE(length(), ConsString::kMinLength);
  CHECK(length() == first()->length() + second()->length());
  if (IsFlat()) {
    // A flat cons can only be created by String::SlowFlatten.
    // Afterwards, the first part may be externalized or internalized.
    CHECK(IsSeqString(first()) || IsExternalString(first()) ||
          IsThinString(first()));
  }
}

void ThinString::ThinStringVerify(Isolate* isolate) {
  StringVerify(isolate);
  CHECK(IsThinString(this, isolate));
  CHECK(!HasForwardingIndex(kAcquireLoad));
  CHECK(IsInternalizedString(actual()));
  CHECK(IsSeqString(actual()) || IsExternalString(actual()));
}

void SlicedString::SlicedStringVerify(Isolate* isolate) {
  StringVerify(isolate);
  CHECK(IsSlicedString(this, isolate));
  CHECK(!IsConsString(parent()));
  CHECK(!IsSlicedString(parent()));
#ifdef DEBUG
  if (!isolate->has_turbofan_string_builders()) {
    // Turbofan's string builder optimization can introduce SlicedString that
    // are less than SlicedString::kMinLength characters. Their live range and
    // scope are pretty limitted, but they can be visible to the GC, which
    // shouldn't treat them as invalid.
    CHECK_GE(length(), SlicedString::kMinLength);
  }
#endif
}

void ExternalString::ExternalStringVerify(Isolate* isolate) {
  StringVerify(isolate);
  CHECK(IsExternalString(this, isolate));
}

void JSBoundFunction::JSBoundFunctionVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSBoundFunctionVerify(*this, isolate);
  CHECK(IsCallable(*this));
  CHECK_EQ(IsConstructor(*this), IsConstructor(bound_target_function()));
  // Ensure that the function's meta map belongs to the same native context
  // as the target function (i.e. meta maps are the same).
  CHECK_EQ(map()->map(), bound_target_function()->map()->map());
}

void JSFunction::JSFunctionVerify(Isolate* isolate) {
  // Don't call TorqueGeneratedClassVerifiers::JSFunctionVerify here because the
  // Torque class definition contains the field `prototype_or_initial_map` which
  // may not be allocated.

  // This assertion exists to encourage updating this verification function if
  // new fields are added in the Torque class layout definition.
  static_assert(JSFunction::TorqueGeneratedClass::kHeaderSize ==
                8 * kTaggedSize);

  JSFunctionOrBoundFunctionOrWrappedFunctionVerify(isolate);
  CHECK(IsJSFunction(*this));
  Object::VerifyPointer(isolate, shared(isolate));
  CHECK(IsSharedFunctionInfo(shared(isolate)));
  Object::VerifyPointer(isolate, context(isolate, kRelaxedLoad));
  CHECK(IsContext(context(isolate, kRelaxedLoad)));
  Object::VerifyPointer(isolate, raw_feedback_cell(isolate));
  CHECK(IsFeedbackCell(raw_feedback_cell(isolate)));
  Object::VerifyPointer(isolate, code(isolate));
  CHECK(IsCode(code(isolate)));
  CHECK(map(isolate)->is_callable());
  // Ensure that the function's meta map belongs to the same native context.
  CHECK_EQ(map()->map()->native_context_or_null(), native_context());

#ifdef V8_ENABLE_LEAPTIERING
  JSDispatchTable* jdt = GetProcessWideJSDispatchTable();
  JSDispatchHandle handle = dispatch_handle();
  CHECK_NE(handle, kNullJSDispatchHandle);
  uint16_t parameter_count = jdt->GetParameterCount(handle);
  CHECK_EQ(parameter_count,
           shared(isolate)->internal_formal_parameter_count_with_receiver());
  Tagged<Code> code_from_table = jdt->GetCode(handle);
  CHECK(code_from_table->parameter_count() == kDontAdaptArgumentsSentinel ||
        code_from_table->parameter_count() == parameter_count);

  // Currently, a JSFunction must have the same dispatch entry as its
  // FeedbackCell, unless the FeedbackCell has no entry.
  JSDispatchHandle feedback_cell_handle =
      raw_feedback_cell(isolate)->dispatch_handle();
  CHECK_EQ(raw_feedback_cell(isolate) == isolate->heap()->many_closures_cell(),
           feedback_cell_handle == kNullJSDispatchHandle);
  if (code_from_table->is_context_specialized()) {
    // This function is context specialized. It must have its own dispatch
    // handle. The canonical handle must exist and be different.
    CHECK_NE(feedback_cell_handle, handle);
  } else {
    // This function is not context specialized. Then we should either use the
    // canonical dispatch handle. Except for builtins, which use the
    // many_closures_cell (see check above).
    // Also, after code flushing this js function can point to the CompileLazy
    // builtin, which will unify the dispatch handles on the next UpdateCode.
    if (feedback_cell_handle != kNullJSDispatchHandle) {
      if (code_from_table->kind() != CodeKind::BUILTIN) {
        CHECK_EQ(feedback_cell_handle, handle);
      }
    }
  }
  if (feedback_cell_handle != kNullJSDispatchHandle) {
    CHECK(!jdt->GetCode(feedback_cell_handle)->is_context_specialized());
  }

  // Verify the entrypoint corresponds to the code or a tiering builtin.
  Address entrypoint = jdt->GetEntrypoint(handle);
#define CASE(name, ...) \
  entrypoint == BUILTIN_CODE(isolate, name)->instruction_start() ||
  CHECK(BUILTIN_LIST_BASE_TIERING(CASE)
            entrypoint == code_from_table->instruction_start());
#undef CASE

#endif  // V8_ENABLE_LEAPTIERING

  Handle<JSFunction> function(*this, isolate);
  LookupIterator it(isolate, function, isolate->factory()->prototype_string(),
                    LookupIterator::OWN_SKIP_INTERCEPTOR);
  if (has_prototype_slot()) {
    VerifyObjectField(isolate, kPrototypeOrInitialMapOffset);
  }

  if (has_prototype_property()) {
    CHECK(it.IsFound());
    CHECK_EQ(LookupIterator::ACCESSOR, it.state());
    CHECK(IsAccessorInfo(*it.GetAccessors()));
  } else {
    CHECK(!it.IsFound() || it.state() != LookupIterator::ACCESSOR ||
          !IsAccessorInfo(*it.GetAccessors()));
  }

  CHECK_IMPLIES(shared()->HasBuiltinId(),
                Builtins::CheckFormalParameterCount(
                    shared()->builtin_id(), shared()->length(),
                    shared()->internal_formal_parameter_count_with_receiver()));
}

void JSWrappedFunction::JSWrappedFunctionVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSWrappedFunctionVerify(*this, isolate);
  CHECK(IsCallable(*this));
  // Ensure that the function's meta map belongs to the same native context.
  CHECK_EQ(map()->map()->native_context_or_null(), context());
}

namespace {

bool ShouldVerifySharedFunctionInfoFunctionIndex(
    Tagged<SharedFunctionInfo> sfi) {
  if (!sfi->HasBuiltinId()) return true;
  switch (sfi->builtin_id()) {
    case Builtin::kPromiseCapabilityDefaultReject:
    case Builtin::kPromiseCapabilityDefaultResolve:
      // For these we manually set custom function indices.
      return false;
    default:
      return true;
  }
  UNREACHABLE();
}

}  // namespace

void SharedFunctionInfo::SharedFunctionInfoVerify(LocalIsolate* isolate) {
  ReadOnlyRoots roots(isolate);

  Tagged<Object> value = name_or_scope_info(kAcquireLoad);
  if (IsScopeInfo(value)) {
    CHECK(!Cast<ScopeInfo>(value)->IsEmpty());
    CHECK_NE(value, roots.empty_scope_info());
  }

#if V8_ENABLE_WEBASSEMBLY
  bool is_wasm = HasWasmExportedFunctionData() || HasAsmWasmData() ||
                 HasWasmJSFunctionData() || HasWasmCapiFunctionData() ||
                 HasWasmResumeData();
#else
  bool is_wasm = false;
#endif  // V8_ENABLE_WEBASSEMBLY
  CHECK(is_wasm || IsApiFunction() || HasBytecodeArray() || HasBuiltinId() ||
        HasUncompiledDataWithPreparseData() ||
        HasUncompiledDataWithoutPreparseData());

  {
    Tagged<HeapObject> script = this->script(kAcquireLoad);
    CHECK(IsUndefined(script, roots) || IsScript(script));
  }

  if (!is_compiled()) {
    CHECK(!HasFeedbackMetadata());
    CHECK(IsScopeInfo(outer_scope_info()) ||
          IsTheHole(outer_scope_info(), roots));
  } else if (HasBytecodeArray() && HasFeedbackMetadata()) {
    CHECK(IsFeedbackMetadata(feedback_metadata()));
  }

  if (HasBytecodeArray() && !IsDontAdaptArguments()) {
    CHECK_EQ(GetBytecodeArray(isolate)->parameter_count(),
             internal_formal_parameter_count_with_receiver());
  }

  if (ShouldVerifySharedFunctionInfoFunctionIndex(*this)) {
    int expected_map_index =
        Context::FunctionMapIndex(language_mode(), kind(), HasSharedName());
    CHECK_EQ(expected_map_index, function_map_index());
  }

  Tagged<ScopeInfo> info = EarlyScopeInfo(kAcquireLoad);
  if (!info->IsEmpty()) {
    CHECK(kind() == info->function_kind());
    CHECK_EQ(internal::IsModule(kind()), info->scope_type() == MODULE_SCOPE);
  }

  if (IsApiFunction()) {
    CHECK(construct_as_builtin());
  } else if (!HasBuiltinId()) {
    CHECK(!construct_as_builtin());
  } else {
    if (builtin_id() != Builtin::kCompileLazy &&
        builtin_id() != Builtin::kEmptyFunction) {
      CHECK(construct_as_builtin());
    } else {
      CHECK(!construct_as_builtin());
    }
  }
  CHECK_IMPLIES(HasBuiltinId(),
                Builtins::CheckFormalParameterCount(
                    builtin_id(), length(),
                    internal_formal_parameter_count_with_receiver()));
}

void SharedFunctionInfo::SharedFunctionInfoVerify(Isolate* isolate) {
  // TODO(leszeks): Add a TorqueGeneratedClassVerifier for LocalIsolate.
  SharedFunctionInfoVerify(isolate->AsLocalIsolate());
}

void SharedFunctionInfoWrapper::SharedFunctionInfoWrapperVerify(
    Isolate* isolate) {
  Object::VerifyPointer(isolate, shared_info());
}

void JSGlobalProxy::JSGlobalProxyVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSGlobalProxyVerify(*this, isolate);
  CHECK(map()->is_access_check_needed());
  // Make sure that this object has no properties, elements.
  CHECK_EQ(0, Cast<FixedArray>(elements())->length());
}

void JSGlobalObject::JSGlobalObjectVerify(Isolate* isolate) {
  CHECK(IsJSGlobalObject(*this));
  // Do not check the dummy global object for the builtins.
  if (global_dictionary(kAcquireLoad)->NumberOfElements() == 0 &&
      elements()->length() == 0) {
    return;
  }
  JSObjectVerify(isolate);
}

void PrimitiveHeapObject::PrimitiveHeapObjectVerify(Isolate* isolate) {
  CHECK(IsPrimitiveHeapObject(this, isolate));
}

void HeapNumber::HeapNumberVerify(Isolate* isolate) {
  PrimitiveHeapObjectVerify(isolate);
  CHECK(IsHeapNumber(this, isolate));
}

void Oddball::OddballVerify(Isolate* isolate) {
  PrimitiveHeapObjectVerify(isolate);
  CHECK(IsOddball(this, isolate));

  Heap* heap = isolate->heap();
  Tagged<Object> string = to_string();
  Object::VerifyPointer(isolate, string);
  CHECK(IsString(string));
  Tagged<Object> type = type_of();
  Object::VerifyPointer(isolate, type);
  CHECK(IsString(type));
  Tagged<Object> kind_value = kind_.load();
  Object::VerifyPointer(isolate, kind_value);
  CHECK(IsSmi(kind_value));

  Tagged<Object> number = to_number();
  Object::VerifyPointer(isolate, number);
  CHECK(IsSmi(number) || IsHeapNumber(number));
  if (IsHeapObject(number)) {
    CHECK(number == ReadOnlyRoots(heap).nan_value() ||
          number == ReadOnlyRoots(heap).hole_nan_value());
  } else {
    CHECK(IsSmi(number));
    int value = Smi::ToInt(number);
    // Hidden oddballs have negative smis.
    const int kLeastHiddenOddballNumber = -7;
    CHECK_LE(value, 1);
    CHECK_GE(value, kLeastHiddenOddballNumber);
  }

  ReadOnlyRoots roots(heap);
  if (map() == roots.undefined_map()) {
    CHECK(this == roots.undefined_value());
  } else if (map() == roots.null_map()) {
    CHECK(this == roots.null_value());
  } else if (map() == roots.boolean_map()) {
    CHECK(this == roots.true_value() || this == roots.false_value());
  } else {
    UNREACHABLE();
  }
}

void Hole::HoleVerify(Isolate* isolate) {
  ReadOnlyRoots roots(isolate->heap());
  CHECK_EQ(map(), roots.hole_map());

#define COMPARE_ROOTS_VALUE(_, Value, __) \
  if (*this == roots.Value()) {           \
    return;                               \
  }
  HOLE_LIST(COMPARE_ROOTS_VALUE);
#undef COMPARE_ROOTS_VALUE

  UNREACHABLE();
}

void PropertyCell::PropertyCellVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::PropertyCellVerify(*this, isolate);
  CHECK(IsUniqueName(name()));
  CheckDataIsCompatible(property_details(), value());
}

void ContextSidePropertyCell::ContextSidePropertyCellVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::ContextSidePropertyCellVerify(*this, isolate);
}

void TrustedObject::TrustedObjectVerify(Isolate* isolate) {
#if defined(V8_ENABLE_SANDBOX)
  // All trusted objects must live in trusted space.
  // TODO(saelo): Some objects are trusted but do not yet live in trusted space.
  CHECK(HeapLayout::InTrustedSpace(*this) || IsCode(*this));
#endif
}

void TrustedObjectLayout::TrustedObjectVerify(Isolate* isolate) {
  UncheckedCast<TrustedObject>(this)->TrustedObjectVerify(isolate);
}

void ExposedTrustedObject::ExposedTrustedObjectVerify(Isolate* isolate) {
  TrustedObjectVerify(isolate);
#if defined(V8_ENABLE_SANDBOX)
  // Check that the self indirect pointer is consistent, i.e. points back to
  // this object.
  InstanceType instance_type = map()->instance_type();
  IndirectPointerTag tag = IndirectPointerTagFromInstanceType(instance_type);
  // We can't use ReadIndirectPointerField here because the tag is not a
  // compile-time constant.
  IndirectPointerSlot slot =
      RawIndirectPointerField(kSelfIndirectPointerOffset, tag);
  Tagged<Object> self = slot.load(isolate);
  CHECK_EQ(self, *this);
  // If the object is in the read-only space, the self indirect pointer entry
  // must be in the read-only segment, and vice versa.
  if (tag == kCodeIndirectPointerTag) {
    CodePointerTable::Space* space =
        IsolateForSandbox(isolate).GetCodePointerTableSpaceFor(slot.address());
    // During snapshot creation, the code pointer space of the read-only heap is
    // not marked as an internal read-only space.
    bool is_space_read_only =
        space == isolate->read_only_heap()->code_pointer_space();
    CHECK_EQ(is_space_read_only, HeapLayout::InReadOnlySpace(*this));
  } else {
    CHECK(!HeapLayout::InReadOnlySpace(*this));
  }
#endif
}

void Code::CodeVerify(Isolate* isolate) {
  ExposedTrustedObjectVerify(isolate);
  CHECK(IsCode(*this));
  if (has_instruction_stream()) {
    Tagged<InstructionStream> istream = instruction_stream();
    CHECK_EQ(istream->code(kAcquireLoad), *this);
    CHECK_EQ(safepoint_table_offset(), 0);
    CHECK_LE(safepoint_table_offset(), handler_table_offset());
    CHECK_LE(handler_table_offset(), constant_pool_offset());
    CHECK_LE(constant_pool_offset(), code_comments_offset());
    CHECK_LE(code_comments_offset(), unwinding_info_offset());
    CHECK_LE(unwinding_info_offset(), metadata_size());

    // Ensure the cached code entry point corresponds to the InstructionStream
    // object associated with this Code.
#if defined(V8_COMPRESS_POINTERS) && defined(V8_SHORT_BUILTIN_CALLS)
    if (istream->instruction_start() == instruction_start()) {
      // Most common case, all good.
    } else {
      // When shared pointer compression cage is enabled and it has the
      // embedded code blob copy then the
      // InstructionStream::instruction_start() might return the address of
      // the remapped builtin regardless of whether the builtins copy existed
      // when the instruction_start value was cached in the Code (see
      // InstructionStream::OffHeapInstructionStart()).  So, do a reverse
      // Code object lookup via instruction_start value to ensure it
      // corresponds to this current Code object.
      Tagged<Code> lookup_result =
          isolate->heap()->FindCodeForInnerPointer(instruction_start());
      CHECK_EQ(lookup_result, *this);
    }
#else
    CHECK_EQ(istream->instruction_start(), instruction_start());
#endif  // V8_COMPRESS_POINTERS && V8_SHORT_BUILTIN_CALLS
  }

  // Our wrapper must point back to us.
  CHECK_EQ(wrapper()->code(isolate), *this);
}

void CodeWrapper::CodeWrapperVerify(Isolate* isolate) {
  if (!this->has_code()) return;
  auto code = this->code(isolate);
  Object::VerifyPointer(isolate, code);
  CHECK_EQ(code->wrapper(), *this);
}

void InstructionStream::InstructionStreamVerify(Isolate* isolate) {
  TrustedObjectVerify(isolate);
  Tagged<Code> code;
  if (!TryGetCode(&code, kAcquireLoad)) return;
  CHECK(
      IsAligned(code->instruction_size(),
                static_cast<unsigned>(InstructionStream::kMetadataAlignment)));
#if (!defined(_MSC_VER) || defined(__clang__)) && !defined(V8_OS_ZOS)
  // See also: PlatformEmbeddedFileWriterWin::AlignToCodeAlignment
  //      and: PlatformEmbeddedFileWriterZOS::AlignToCodeAlignment
  CHECK_IMPLIES(!ReadOnlyHeap::Contains(*this),
                IsAligned(instruction_start(), kCodeAlignment));
#endif  // (!defined(_MSC_VER) || defined(__clang__)) && !defined(V8_OS_ZOS)
  CHECK_IMPLIES(!ReadOnlyHeap::Contains(*this),
                IsAligned(instruction_start(), kCodeAlignment));
  CHECK_EQ(*this, code->instruction_stream());
  CHECK(Size() <= MemoryChunkLayout::MaxRegularCodeObjectSize() ||
        isolate->heap()->InSpace(*this, CODE_LO_SPACE));
  Address last_gc_pc = kNullAddress;

  Object::ObjectVerify(relocation_info(), isolate);

  for (RelocIterator it(code); !it.done(); it.next()) {
    it.rinfo()->Verify(isolate);
    // Ensure that GC will not iterate twice over the same pointer.
    if (RelocInfo::IsGCRelocMode(it.rinfo()->rmode())) {
      CHECK(it.rinfo()->pc() != last_gc_pc);
      last_gc_pc = it.rinfo()->pc();
    }
  }
}

void JSArray::JSArrayVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSArrayVerify(*this, isolate);
  // If a GC was caused while constructing this array, the elements
  // pointer may point to a one pointer filler map.
  if (!ElementsAreSafeToExamine(isolate)) return;
  if (IsUndefined(elements(), isolate)) return;
  CHECK(IsFixedArray(elements()) || IsFixedDoubleArray(elements()));
  if (elements()->length() == 0) {
    CHECK_EQ(elements(), ReadOnlyRoots(isolate).empty_fixed_array());
  }
  // Verify that the length and the elements backing store are in sync.
  if (IsSmi(length()) && (HasFastElements() || HasAnyNonextensibleElements())) {
    if (elements()->length() > 0) {
      CHECK_IMPLIES(HasDoubleElements(), IsFixedDoubleArray(elements()));
      CHECK_IMPLIES(HasSmiOrObjectElements() || HasAnyNonextensibleElements(),
                    IsFixedArray(elements()));
    }
    int size = Smi::ToInt(length());
    // Holey / Packed backing stores might have slack or might have not been
    // properly initialized yet.
    CHECK(size <= elements()->length() ||
          elements() == ReadOnlyRoots(isolate).empty_fixed_array());
  } else {
    CHECK(HasDictionaryElements());
    uint32_t array_length;
    CHECK(Object::ToArrayLength(length(), &array_length));
    if (array_length == 0xFFFFFFFF) {
      CHECK(Object::ToArrayLength(length(), &array_length));
    }
    if (array_length != 0) {
      Tagged<NumberDictionary> dict = Cast<NumberDictionary>(elements());
      // The dictionary can never have more elements than the array length + 1.
      // If the backing store grows the verification might be triggered with
      // the old length in place.
      uint32_t nof_elements = static_cast<uint32_t>(dict->NumberOfElements());
      if (nof_elements != 0) nof_elements--;
      CHECK_LE(nof_elements, array_length);
    }
  }
}

void JSSet::JSSetVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSSetVerify(*this, isolate);
  CHECK(IsOrderedHashSet(table()) || IsUndefined(table(), isolate));
  // TODO(arv): Verify OrderedHashTable too.
}

void JSMap::JSMapVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSMapVerify(*this, isolate);
  CHECK(IsOrderedHashMap(table()) || IsUndefined(table(), isolate));
  // TODO(arv): Verify OrderedHashTable too.
}

void JSSetIterator::JSSetIteratorVerify(Isolate* isolate) {
  CHECK(IsJSSetIterator(*this));
  JSCollectionIteratorVerify(isolate);
  CHECK(IsOrderedHashSet(table()));
  CHECK(IsSmi(index()));
}

void JSMapIterator::JSMapIteratorVerify(Isolate* isolate) {
  CHECK(IsJSMapIterator(*this));
  JSCollectionIteratorVerify(isolate);
  CHECK(IsOrderedHashMap(table()));
  CHECK(IsSmi(index()));
}

USE_TORQUE_VERIFIER(JSShadowRealm)

namespace {

void VerifyElementIsShared(Tagged<Object> element) {
  // Exception for ThinStrings:
  // When storing a ThinString in a shared object, we want to store the actual
  // string, which is shared when sharing the string table.
  // It is possible that a stored shared string migrates to a ThinString later
  // on, which is fine as the ThinString resides in shared space if the original
  // string was in shared space.
  if (IsThinStrin
```