Response: The user wants a summary of the C++ code in `v8/src/ic/accessor-assembler.cc`.
The code seems to be related to how V8 accesses properties in JavaScript, likely as part of the Inline Cache (IC) system.
It uses an assembler (`AccessorAssembler`) to generate optimized code for property access.

Key observations from the included headers and the code:
- It deals with different types of property access: loads and stores.
- It handles various property kinds (fields, constants, accessors, etc.).
- It interacts with the feedback vector, which stores information about previous property accesses for optimization.
- It handles polymorphic cases (where a property might exist on different object shapes).
- It considers API getters and setters.
- It handles elements (array indices).
- It includes specific logic for WebAssembly.

Therefore, the core functionality is generating efficient machine code for accessing object properties in JavaScript based on the observed types and structures.
这个C++源代码文件 `accessor-assembler.cc` 的主要功能是**构建和管理用于高效访问JavaScript对象属性的汇编代码片段（stubs）**。 它是V8引擎中内联缓存（Inline Cache，IC）系统的一部分。

更具体地说，这个文件定义了一个 `AccessorAssembler` 类，它提供了一组用于生成各种属性访问操作的汇编指令的工具函数。 这些操作包括：

- **加载属性 (Load)**：从对象中读取属性值。
- **存储属性 (Store)**：向对象写入属性值。
- **处理不同类型的属性**：例如，字段 (fields)、常量 (constants)、访问器属性 (accessor properties)、原型链上的属性等。
- **优化策略**：利用内联缓存的反馈信息 (feedback vector) 来生成更快的代码，例如处理单态 (monomorphic) 和多态 (polymorphic) 的情况。
- **处理特殊情况**：例如，访问 API 对象 (API object)、WebAssembly 对象 (Wasm object) 的属性。

**与 JavaScript 功能的关系和示例**

`accessor-assembler.cc`  直接影响 JavaScript 属性访问的性能。当 JavaScript 代码尝试访问对象的属性时，V8 引擎会尝试使用内联缓存来加速这个过程。 `AccessorAssembler` 生成的汇编代码片段正是内联缓存的核心。

**JavaScript 示例：**

假设有以下 JavaScript 代码：

```javascript
const obj = { x: 10 };
const value = obj.x; // 属性加载
obj.y = 20;         // 属性存储
```

当 V8 引擎第一次执行 `obj.x` 时，可能会生成一个通用的属性加载的汇编代码。但是，随着代码的运行，如果 V8 发现 `obj` 的形状 (shape，也就是它的属性和类型) 没有发生变化，它可以使用 `AccessorAssembler` 生成一个更优化的汇编代码片段，直接从 `obj` 对象内部的特定偏移量读取 `x` 的值，而无需进行复杂的查找。

同样，对于 `obj.y = 20`，`AccessorAssembler` 可以生成优化的汇编代码来直接写入 `y` 的值。

**更复杂的例子，涉及原型和访问器：**

```javascript
class MyClass {
  constructor() {
    this._privateValue = 42;
  }

  get publicValue() {
    return this._privateValue * 2;
  }

  set publicValue(newValue) {
    this._privateValue = newValue / 2;
  }
}

const instance = new MyClass();
const publicVal = instance.publicValue; // 调用 getter
instance.publicValue = 100;             // 调用 setter
```

在这个例子中，当访问 `instance.publicValue` 时，`AccessorAssembler` 会生成调用 `publicValue` getter 函数的汇编代码。当设置 `instance.publicValue` 时，会生成调用 setter 函数的汇编代码。 `AccessorAssembler` 还会处理原型链上的属性查找，确保能正确找到并调用 `MyClass` 原型上的 getter 和 setter。

**总结**

`accessor-assembler.cc` 是 V8 引擎中负责生成高效的属性访问代码的关键组成部分。它通过使用汇编指令和内联缓存的反馈信息，显著提升了 JavaScript 代码中属性访问的性能。

### 提示词
```
这是目录为v8/src/ic/accessor-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/ic/accessor-assembler.h"

#include <optional>

#include "src/ast/ast.h"
#include "src/builtins/builtins-constructor-gen.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/ic/handler-configuration.h"
#include "src/ic/ic.h"
#include "src/ic/keyed-store-generic.h"
#include "src/ic/stub-cache.h"
#include "src/logging/counters.h"
#include "src/objects/cell.h"
#include "src/objects/dictionary.h"
#include "src/objects/feedback-vector.h"
#include "src/objects/foreign.h"
#include "src/objects/heap-number.h"
#include "src/objects/megadom-handler.h"
#include "src/objects/module.h"
#include "src/objects/objects-inl.h"
#include "src/objects/property-details.h"
#include "src/objects/smi.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

//////////////////// Private helpers.

#define LOAD_KIND(kind) \
  Int32Constant(static_cast<intptr_t>(LoadHandler::Kind::kind))
#define STORE_KIND(kind) \
  Int32Constant(static_cast<intptr_t>(StoreHandler::Kind::kind))

// Loads dataX field from the DataHandler object.
TNode<MaybeObject> AccessorAssembler::LoadHandlerDataField(
    TNode<DataHandler> handler, int data_index) {
#ifdef DEBUG
  TNode<Map> handler_map = LoadMap(handler);
  TNode<Uint16T> instance_type = LoadMapInstanceType(handler_map);
#endif
  CSA_DCHECK(this,
             Word32Or(InstanceTypeEqual(instance_type, LOAD_HANDLER_TYPE),
                      InstanceTypeEqual(instance_type, STORE_HANDLER_TYPE)));
  int offset = 0;
  int minimum_size = 0;
  switch (data_index) {
    case 1:
      offset = DataHandler::kData1Offset;
      minimum_size = DataHandler::kSizeWithData1;
      break;
    case 2:
      offset = DataHandler::kData2Offset;
      minimum_size = DataHandler::kSizeWithData2;
      break;
    case 3:
      offset = DataHandler::kData3Offset;
      minimum_size = DataHandler::kSizeWithData3;
      break;
    default:
      UNREACHABLE();
  }
  USE(minimum_size);
  CSA_DCHECK(this, UintPtrGreaterThanOrEqual(
                       LoadMapInstanceSizeInWords(handler_map),
                       IntPtrConstant(minimum_size / kTaggedSize)));
  return LoadMaybeWeakObjectField(handler, offset);
}

TNode<HeapObjectReference> AccessorAssembler::TryMonomorphicCase(
    TNode<TaggedIndex> slot, TNode<FeedbackVector> vector,
    TNode<HeapObjectReference> weak_lookup_start_object_map, Label* if_handler,
    TVariable<MaybeObject>* var_handler, Label* if_miss) {
  Comment("TryMonomorphicCase");
  DCHECK_EQ(MachineRepresentation::kTagged, var_handler->rep());

  // TODO(ishell): add helper class that hides offset computations for a series
  // of loads.
  int32_t header_size =
      FeedbackVector::kRawFeedbackSlotsOffset - kHeapObjectTag;
  // Adding |header_size| with a separate IntPtrAdd rather than passing it
  // into ElementOffsetFromIndex() allows it to be folded into a single
  // [base, index, offset] indirect memory access on x64.
  TNode<IntPtrT> offset = ElementOffsetFromIndex(slot, HOLEY_ELEMENTS);
  TNode<HeapObjectReference> feedback = CAST(Load<MaybeObject>(
      vector, IntPtrAdd(offset, IntPtrConstant(header_size))));

  // Try to quickly handle the monomorphic case without knowing for sure
  // if we have a weak reference in feedback.
  CSA_DCHECK(this,
             IsMap(GetHeapObjectAssumeWeak(weak_lookup_start_object_map)));
  GotoIfNot(TaggedEqual(feedback, weak_lookup_start_object_map), if_miss);

  TNode<MaybeObject> handler = UncheckedCast<MaybeObject>(
      Load(MachineType::AnyTagged(), vector,
           IntPtrAdd(offset, IntPtrConstant(header_size + kTaggedSize))));

  *var_handler = handler;
  Goto(if_handler);
  return feedback;
}

void AccessorAssembler::HandlePolymorphicCase(
    TNode<HeapObjectReference> weak_lookup_start_object_map,
    TNode<WeakFixedArray> feedback, Label* if_handler,
    TVariable<MaybeObject>* var_handler, Label* if_miss) {
  Comment("HandlePolymorphicCase");
  DCHECK_EQ(MachineRepresentation::kTagged, var_handler->rep());

  // Iterate {feedback} array.
  const int kEntrySize = 2;

  // Load the {feedback} array length.
  TNode<Int32T> length =
      Signed(LoadAndUntagWeakFixedArrayLengthAsUint32(feedback));
  CSA_DCHECK(this, Int32LessThanOrEqual(Int32Constant(kEntrySize), length));

  // This is a hand-crafted loop that iterates backwards and only compares
  // against zero at the end, since we already know that we will have at least a
  // single entry in the {feedback} array anyways.
  TVARIABLE(Int32T, var_index, Int32Sub(length, Int32Constant(kEntrySize)));
  Label loop(this, &var_index), loop_next(this);
  Goto(&loop);
  BIND(&loop);
  {
    TNode<IntPtrT> index = ChangePositiveInt32ToIntPtr(var_index.value());
    TNode<MaybeObject> maybe_cached_map =
        LoadWeakFixedArrayElement(feedback, index);
    CSA_DCHECK(this,
               IsMap(GetHeapObjectAssumeWeak(weak_lookup_start_object_map)));
    GotoIfNot(TaggedEqual(maybe_cached_map, weak_lookup_start_object_map),
              &loop_next);

    // Found, now call handler.
    TNode<MaybeObject> handler =
        LoadWeakFixedArrayElement(feedback, index, kTaggedSize);
    *var_handler = handler;
    Goto(if_handler);

    BIND(&loop_next);
    var_index = Int32Sub(var_index.value(), Int32Constant(kEntrySize));
    Branch(Int32GreaterThanOrEqual(var_index.value(), Int32Constant(0)), &loop,
           if_miss);
  }
}

void AccessorAssembler::TryMegaDOMCase(TNode<Object> lookup_start_object,
                                       TNode<Map> lookup_start_object_map,
                                       TVariable<MaybeObject>* var_handler,
                                       TNode<Object> vector,
                                       TNode<TaggedIndex> slot, Label* miss,
                                       ExitPoint* exit_point) {
  // Check if the receiver is a JS_API_OBJECT
  GotoIfNot(IsJSApiObjectMap(lookup_start_object_map), miss);

  // Check if receiver requires access check
  GotoIf(IsSetWord32<Map::Bits1::IsAccessCheckNeededBit>(
             LoadMapBitField(lookup_start_object_map)),
         miss);

  CSA_DCHECK(this, TaggedEqual(LoadFeedbackVectorSlot(CAST(vector), slot),
                               MegaDOMSymbolConstant()));

  // In some cases, we load the
  TNode<MegaDomHandler> handler;
  if (var_handler->IsBound()) {
    handler = CAST(var_handler->value());
  } else {
    TNode<MaybeObject> maybe_handler =
        LoadFeedbackVectorSlot(CAST(vector), slot, kTaggedSize);
    CSA_DCHECK(this, IsStrong(maybe_handler));
    handler = CAST(maybe_handler);
  }

  // Check if dom protector cell is still valid
  GotoIf(IsMegaDOMProtectorCellInvalid(), miss);

  // Load the getter
  TNode<MaybeObject> maybe_getter = LoadMegaDomHandlerAccessor(handler);
  CSA_DCHECK(this, IsWeakOrCleared(maybe_getter));
  TNode<FunctionTemplateInfo> getter =
      CAST(GetHeapObjectAssumeWeak(maybe_getter, miss));

  // Load the accessor context
  TNode<MaybeObject> maybe_context = LoadMegaDomHandlerContext(handler);
  CSA_DCHECK(this, IsWeakOrCleared(maybe_context));
  TNode<Context> context = CAST(GetHeapObjectAssumeWeak(maybe_context, miss));

  // TODO(gsathya): This builtin throws an exception on interface check fail but
  // we should miss to the runtime.
  TNode<Context> caller_context = context;
  exit_point->Return(CallBuiltin(Builtin::kCallFunctionTemplate_Generic,
                                 context, getter, Int32Constant(1),
                                 caller_context, lookup_start_object));
}

void AccessorAssembler::TryEnumeratedKeyedLoad(
    const LoadICParameters* p, TNode<Map> lookup_start_object_map,
    ExitPoint* exit_point) {
  if (!p->IsEnumeratedKeyedLoad()) return;
  Label no_enum_cache(this);
  // |p->cache_type()| comes from the outer loop's ForIn state.
  GotoIf(TaggedNotEqual(p->cache_type(), lookup_start_object_map),
         &no_enum_cache);

  // Use field index in EnumCache.
  TNode<DescriptorArray> descriptors =
      LoadMapDescriptors(lookup_start_object_map);
  TNode<EnumCache> enum_cache = LoadObjectField<EnumCache>(
      descriptors, DescriptorArray::kEnumCacheOffset);
  TNode<FixedArray> enum_keys =
      LoadObjectField<FixedArray>(enum_cache, EnumCache::kKeysOffset);
  // |p->enum_index()| comes from the outer loop's ForIn state.
  TNode<Object> key = LoadFixedArrayElement(enum_keys, p->enum_index());
  // Check if |p->name()| matches the key in enum cache. |p->name()| is the
  // "each" variable of a for-in loop, but it can be modified by debugger or
  // other bytecodes.
  GotoIf(TaggedNotEqual(key, p->name()), &no_enum_cache);
  TNode<FixedArray> enum_indices =
      LoadObjectField<FixedArray>(enum_cache, EnumCache::kIndicesOffset);
  // Check if we have enum indices available.
  GotoIf(IsEmptyFixedArray(enum_indices), &no_enum_cache);
  TNode<Int32T> field_index =
      SmiToInt32(CAST(LoadFixedArrayElement(enum_indices, p->enum_index())));

  TVARIABLE(Object, result);
  Label if_double(this, Label::kDeferred), done(this, &result);
  // Check if field is a mutable double field.
  uint32_t kIsMutableDoubleFieldMask = 1;
  GotoIf(IsSetWord32(field_index, kIsMutableDoubleFieldMask), &if_double);

  TNode<Int32T> zero = Int32Constant(0);
  {
    Label if_outofobject(this);
    // Check if field is in-object or out-of-object.
    GotoIf(Int32LessThan(field_index, zero), &if_outofobject);

    // The field is located in the {object} itself.
    {
      TNode<IntPtrT> offset = Signed(ChangeUint32ToWord(
          Int32Add(Word32Shl(field_index, Int32Constant(kTaggedSizeLog2 - 1)),
                   Int32Constant(JSObject::kHeaderSize))));
      result =
          LoadObjectField(CAST(p->receiver_and_lookup_start_object()), offset);
      Goto(&done);
    }

    // The field is located in the properties backing store of {object}.
    // The {index} is equal to the negated out of property index plus 1.
    BIND(&if_outofobject);
    {
      TNode<PropertyArray> properties = CAST(LoadFastProperties(
          CAST(p->receiver_and_lookup_start_object()), true));
      TNode<IntPtrT> offset = Signed(ChangeUint32ToWord(Int32Add(
          Word32Shl(Int32Sub(zero, field_index),
                    Int32Constant(kTaggedSizeLog2 - 1)),
          Int32Constant(OFFSET_OF_DATA_START(FixedArray) - kTaggedSize))));
      result = LoadObjectField(properties, offset);
      Goto(&done);
    }
  }

  // The field is a Double field, either unboxed in the object on 64-bit
  // architectures, or a mutable HeapNumber.
  BIND(&if_double);
  {
    TVARIABLE(Object, field);
    Label loaded_field(this, &field), if_outofobject(this);
    field_index = Word32Sar(field_index, Int32Constant(1));
    // Check if field is in-object or out-of-object.
    GotoIf(Int32LessThan(field_index, zero), &if_outofobject);

    // The field is located in the {object} itself.
    {
      TNode<IntPtrT> offset = Signed(ChangeUint32ToWord(
          Int32Add(Word32Shl(field_index, Int32Constant(kTaggedSizeLog2)),
                   Int32Constant(JSObject::kHeaderSize))));
      field =
          LoadObjectField(CAST(p->receiver_and_lookup_start_object()), offset);
      Goto(&loaded_field);
    }

    BIND(&if_outofobject);
    {
      TNode<PropertyArray> properties = CAST(LoadFastProperties(
          CAST(p->receiver_and_lookup_start_object()), true));
      TNode<IntPtrT> offset = Signed(ChangeUint32ToWord(Int32Add(
          Word32Shl(Int32Sub(zero, field_index),
                    Int32Constant(kTaggedSizeLog2)),
          Int32Constant(OFFSET_OF_DATA_START(FixedArray) - kTaggedSize))));
      field = LoadObjectField(properties, offset);
      Goto(&loaded_field);
    }

    BIND(&loaded_field);
    {
      // We may have transitioned in-place away from double, so check that
      // this is a HeapNumber -- otherwise the load is fine and we don't need
      // to copy anything anyway.
      Label if_not_double(this);
      GotoIf(TaggedIsSmi(field.value()), &if_not_double);

      TNode<HeapObject> double_field = CAST(field.value());
      TNode<Map> field_map = LoadMap(double_field);
      GotoIfNot(TaggedEqual(field_map, HeapNumberMapConstant()),
                &if_not_double);

      TNode<Float64T> value = LoadHeapNumberValue(double_field);
      result = AllocateHeapNumberWithValue(value);
      Goto(&done);

      BIND(&if_not_double);
      {
        result = field.value();
        Goto(&done);
      }
    }
  }

  BIND(&done);
  { exit_point->Return(result.value()); }

  BIND(&no_enum_cache);
}

void AccessorAssembler::HandleLoadICHandlerCase(
    const LazyLoadICParameters* p, TNode<MaybeObject> handler, Label* miss,
    ExitPoint* exit_point, ICMode ic_mode, OnNonExistent on_nonexistent,
    ElementSupport support_elements, LoadAccessMode access_mode) {
  Comment("have_handler");

  TVARIABLE(Object, var_holder, p->lookup_start_object());
  TVARIABLE(MaybeObject, var_smi_handler, handler);

  Label if_smi_handler(this, {&var_holder, &var_smi_handler});
  Label try_proto_handler(this, Label::kDeferred),
      call_code_handler(this, Label::kDeferred),
      call_getter(this, Label::kDeferred);

  Branch(TaggedIsSmi(handler), &if_smi_handler, &try_proto_handler);

  BIND(&try_proto_handler);
  {
    GotoIf(IsWeakOrCleared(handler), &call_getter);
    GotoIf(IsCode(CAST(handler)), &call_code_handler);
    HandleLoadICProtoHandler(p, CAST(handler), &var_holder, &var_smi_handler,
                             &if_smi_handler, miss, exit_point, ic_mode,
                             access_mode);
  }

  // |handler| is a Smi, encoding what to do. See SmiHandler methods
  // for the encoding format.
  BIND(&if_smi_handler);
  {
    HandleLoadICSmiHandlerCase(
        p, var_holder.value(), CAST(var_smi_handler.value()), handler, miss,
        exit_point, ic_mode, on_nonexistent, support_elements, access_mode);
  }

  BIND(&call_getter);
  {
    if (access_mode == LoadAccessMode::kHas) {
      exit_point->Return(TrueConstant());
    } else {
      TNode<HeapObject> strong_handler = GetHeapObjectAssumeWeak(handler, miss);
      TNode<JSFunction> getter =
          CAST(LoadAccessorPairGetter(CAST(strong_handler)));

      ConvertReceiverMode mode =
          p->lookup_start_object() == p->receiver()
              // LoadIC case: the receiver is definitely not null or undefined.
              ? ConvertReceiverMode::kNotNullOrUndefined
              // LoadSuperIC case: the receiver might be anything.
              : ConvertReceiverMode::kAny;
      exit_point->Return(
          CallFunction(p->context(), getter, mode, p->receiver()));
    }
  }

  BIND(&call_code_handler);
  {
    TNode<Code> code_handler = CAST(handler);
    exit_point->ReturnCallStub(LoadWithVectorDescriptor{}, code_handler,
                               p->context(), p->lookup_start_object(),
                               p->name(), p->slot(), p->vector());
  }
}

void AccessorAssembler::HandleLoadCallbackProperty(
    const LazyLoadICParameters* p, TNode<JSObject> holder,
    TNode<Word32T> handler_word, ExitPoint* exit_point) {
  Comment("native_data_property_load");
  TNode<IntPtrT> descriptor =
      Signed(DecodeWordFromWord32<LoadHandler::DescriptorBits>(handler_word));

  TNode<AccessorInfo> accessor_info =
      CAST(LoadDescriptorValue(LoadMap(holder), descriptor));

  exit_point->ReturnCallBuiltin(Builtin::kCallApiGetter, p->context(),
                                p->receiver(), holder, accessor_info);
}

void AccessorAssembler::HandleLoadAccessor(
    const LazyLoadICParameters* p,
    TNode<FunctionTemplateInfo> function_template_info,
    TNode<Word32T> handler_word, TNode<DataHandler> handler,
    TNode<Uint32T> handler_kind, ExitPoint* exit_point) {
  Comment("api_getter");
  // Context is stored either in data2 or data3 field depending on whether
  // the access check is enabled for this handler or not.
  TNode<MaybeObject> maybe_context = Select<MaybeObject>(
      IsSetWord32<LoadHandler::DoAccessCheckOnLookupStartObjectBits>(
          handler_word),
      [=, this] { return LoadHandlerDataField(handler, 3); },
      [=, this] { return LoadHandlerDataField(handler, 2); });

  CSA_DCHECK(this, IsWeakOrCleared(maybe_context));
  CSA_CHECK(this, IsNotCleared(maybe_context));
  TNode<HeapObject> context = GetHeapObjectAssumeWeak(maybe_context);

  TVARIABLE(HeapObject, api_holder, CAST(p->lookup_start_object()));
  Label load(this);
  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kApiGetter)), &load);

  CSA_DCHECK(this,
             Word32Equal(handler_kind, LOAD_KIND(kApiGetterHolderIsPrototype)));

  api_holder = LoadMapPrototype(LoadMap(CAST(p->lookup_start_object())));
  Goto(&load);

  BIND(&load);
  {
    TNode<Int32T> argc = Int32Constant(0);
    TNode<Context> caller_context = p->context();
    exit_point->Return(CallBuiltin(Builtin::kCallApiCallbackGeneric, context,
                                   argc, caller_context, function_template_info,
                                   api_holder.value(), p->receiver()));
  }
}

void AccessorAssembler::HandleLoadField(TNode<JSObject> holder,
                                        TNode<Word32T> handler_word,
                                        TVariable<Float64T>* var_double_value,
                                        Label* rebox_double, Label* miss,
                                        ExitPoint* exit_point) {
  Comment("LoadField");
  TNode<IntPtrT> index =
      Signed(DecodeWordFromWord32<LoadHandler::FieldIndexBits>(handler_word));
  TNode<IntPtrT> offset = IntPtrMul(index, IntPtrConstant(kTaggedSize));

  TNode<BoolT> is_inobject =
      IsSetWord32<LoadHandler::IsInobjectBits>(handler_word);
  TNode<HeapObject> property_storage = Select<HeapObject>(
      is_inobject, [&]() { return holder; },
      [&]() { return LoadFastProperties(holder, true); });

  Label is_double(this);
  TNode<Object> value = LoadObjectField(property_storage, offset);
  GotoIf(IsSetWord32<LoadHandler::IsDoubleBits>(handler_word), &is_double);
  exit_point->Return(value);

  BIND(&is_double);
  // This is not an "old" Smi value from before a Smi->Double transition.
  // Rather, it's possible that since the last update of this IC, the Double
  // field transitioned to a Tagged field, and was then assigned a Smi.
  GotoIf(TaggedIsSmi(value), miss);
  GotoIfNot(IsHeapNumber(CAST(value)), miss);
  *var_double_value = LoadHeapNumberValue(CAST(value));
  Goto(rebox_double);
}

#if V8_ENABLE_WEBASSEMBLY

void AccessorAssembler::HandleLoadWasmField(
    TNode<WasmObject> holder, TNode<Int32T> wasm_value_type,
    TNode<IntPtrT> field_offset, TVariable<Float64T>* var_double_value,
    Label* rebox_double, ExitPoint* exit_point) {
  Label type_I8(this), type_I16(this), type_I32(this), type_U32(this),
      type_I64(this), type_U64(this), type_F32(this), type_F64(this),
      type_Ref(this), unsupported_type(this, Label::kDeferred),
      unexpected_type(this, Label::kDeferred);
  Label* wasm_value_type_labels[] = {
      &type_I8,  &type_I16, &type_I32, &type_U32, &type_I64,
      &type_F32, &type_F64, &type_Ref, &type_Ref, &unsupported_type};
  int32_t wasm_value_types[] = {
      static_cast<int32_t>(WasmValueType::kI8),
      static_cast<int32_t>(WasmValueType::kI16),
      static_cast<int32_t>(WasmValueType::kI32),
      static_cast<int32_t>(WasmValueType::kU32),
      static_cast<int32_t>(WasmValueType::kI64),
      static_cast<int32_t>(WasmValueType::kF32),
      static_cast<int32_t>(WasmValueType::kF64),
      static_cast<int32_t>(WasmValueType::kRef),
      static_cast<int32_t>(WasmValueType::kRefNull),
      // TODO(v8:11804): support the following value types.
      static_cast<int32_t>(WasmValueType::kS128)};
  const size_t kWasmValueTypeCount =
      static_cast<size_t>(WasmValueType::kNumTypes);
  DCHECK_EQ(kWasmValueTypeCount, arraysize(wasm_value_types));
  DCHECK_EQ(kWasmValueTypeCount, arraysize(wasm_value_type_labels));

  Switch(wasm_value_type, &unexpected_type, wasm_value_types,
         wasm_value_type_labels, kWasmValueTypeCount);
  BIND(&type_I8);
  {
    Comment("type_I8");
    TNode<Int32T> value = LoadObjectField<Int8T>(holder, field_offset);
    exit_point->Return(SmiFromInt32(value));
  }
  BIND(&type_I16);
  {
    Comment("type_I16");
    TNode<Int32T> value = LoadObjectField<Int16T>(holder, field_offset);
    exit_point->Return(SmiFromInt32(value));
  }
  BIND(&type_I32);
  {
    Comment("type_I32");
    TNode<Int32T> value = LoadObjectField<Int32T>(holder, field_offset);
    exit_point->Return(ChangeInt32ToTagged(value));
  }
  BIND(&type_U32);
  {
    Comment("type_U32");
    TNode<Uint32T> value = LoadObjectField<Uint32T>(holder, field_offset);
    exit_point->Return(ChangeUint32ToTagged(value));
  }
  BIND(&type_I64);
  {
    Comment("type_I64");
    TNode<RawPtrT> data_pointer =
        ReinterpretCast<RawPtrT>(BitcastTaggedToWord(holder));
    TNode<BigInt> value = LoadFixedBigInt64ArrayElementAsTagged(
        data_pointer,
        Signed(IntPtrSub(field_offset, IntPtrConstant(kHeapObjectTag))));
    exit_point->Return(value);
  }
  BIND(&type_F32);
  {
    Comment("type_F32");
    TNode<Float32T> value = LoadObjectField<Float32T>(holder, field_offset);
    *var_double_value = ChangeFloat32ToFloat64(value);
    Goto(rebox_double);
  }
  BIND(&type_F64);
  {
    Comment("type_F64");
    TNode<Float64T> value = LoadObjectField<Float64T>(holder, field_offset);
    *var_double_value = value;
    Goto(rebox_double);
  }
  BIND(&type_Ref);
  {
    Comment("type_Ref");
    TNode<Object> value = LoadObjectField(holder, field_offset);
    exit_point->Return(value);
  }
  BIND(&unsupported_type);
  {
    Print("Not supported Wasm field type");
    Unreachable();
  }
  BIND(&unexpected_type);
  { Unreachable(); }
}

void AccessorAssembler::HandleLoadWasmField(
    TNode<WasmObject> holder, TNode<Word32T> handler_word,
    TVariable<Float64T>* var_double_value, Label* rebox_double,
    ExitPoint* exit_point) {
  Comment("LoadWasmField");
  TNode<Int32T> wasm_value_type =
      Signed(DecodeWord32<LoadHandler::WasmFieldTypeBits>(handler_word));
  TNode<IntPtrT> field_offset = Signed(
      DecodeWordFromWord32<LoadHandler::WasmFieldOffsetBits>(handler_word));

  HandleLoadWasmField(holder, wasm_value_type, field_offset, var_double_value,
                      rebox_double, exit_point);
}

#endif  // V8_ENABLE_WEBASSEMBLY

TNode<Object> AccessorAssembler::LoadDescriptorValue(
    TNode<Map> map, TNode<IntPtrT> descriptor_entry) {
  return CAST(LoadDescriptorValueOrFieldType(map, descriptor_entry));
}

TNode<MaybeObject> AccessorAssembler::LoadDescriptorValueOrFieldType(
    TNode<Map> map, TNode<IntPtrT> descriptor_entry) {
  TNode<DescriptorArray> descriptors = LoadMapDescriptors(map);
  return LoadFieldTypeByDescriptorEntry(descriptors, descriptor_entry);
}

void AccessorAssembler::HandleLoadICSmiHandlerCase(
    const LazyLoadICParameters* p, TNode<Object> holder, TNode<Smi> smi_handler,
    TNode<MaybeObject> handler, Label* miss, ExitPoint* exit_point,
    ICMode ic_mode, OnNonExistent on_nonexistent,
    ElementSupport support_elements, LoadAccessMode access_mode) {
  TVARIABLE(Float64T, var_double_value);
  Label rebox_double(this, &var_double_value);

  TNode<Int32T> handler_word = SmiToInt32(smi_handler);
  TNode<Uint32T> handler_kind =
      DecodeWord32<LoadHandler::KindBits>(handler_word);

  if (support_elements == kSupportElements) {
    Label if_element(this), if_indexed_string(this), if_property(this),
        if_hole(this), unimplemented_elements_kind(this),
        if_oob(this, Label::kDeferred), try_string_to_array_index(this),
        emit_element_load(this);
    TVARIABLE(IntPtrT, var_intptr_index);
    GotoIf(Word32Equal(handler_kind, LOAD_KIND(kElement)), &if_element);

    if (access_mode == LoadAccessMode::kHas) {
      CSA_DCHECK(this, Word32NotEqual(handler_kind, LOAD_KIND(kIndexedString)));
      Goto(&if_property);
    } else {
      Branch(Word32Equal(handler_kind, LOAD_KIND(kIndexedString)),
             &if_indexed_string, &if_property);
    }

    BIND(&if_element);
    {
      Comment("element_load");
      // TODO(ishell): implement
      CSA_DCHECK(this,
                 IsClearWord32<LoadHandler::IsWasmArrayBits>(handler_word));
      TVARIABLE(Int32T, var_instance_type);
      TNode<IntPtrT> intptr_index = TryToIntptr(
          p->name(), &try_string_to_array_index, &var_instance_type);
      var_intptr_index = intptr_index;
      Goto(&emit_element_load);

      BIND(&try_string_to_array_index);
      {
        GotoIfNot(IsStringInstanceType(var_instance_type.value()), miss);

        TNode<ExternalReference> function = ExternalConstant(
            ExternalReference::string_to_array_index_function());
        TNode<Int32T> result = UncheckedCast<Int32T>(
            CallCFunction(function, MachineType::Int32(),
                          std::make_pair(MachineType::AnyTagged(), p->name())));
        GotoIf(Word32Equal(Int32Constant(-1), result), miss);
        CSA_DCHECK(this, Int32GreaterThanOrEqual(result, Int32Constant(0)));
        var_intptr_index = ChangeInt32ToIntPtr(result);

        Goto(&emit_element_load);
      }

      BIND(&emit_element_load);
      {
        TNode<BoolT> is_jsarray_condition =
            IsSetWord32<LoadHandler::IsJsArrayBits>(handler_word);
        TNode<Uint32T> elements_kind =
            DecodeWord32<LoadHandler::ElementsKindBits>(handler_word);
        EmitElementLoad(CAST(holder), elements_kind, var_intptr_index.value(),
                        is_jsarray_condition, &if_hole, &rebox_double,
                        &var_double_value, &unimplemented_elements_kind,
                        &if_oob, miss, exit_point, access_mode);
      }
    }

    BIND(&unimplemented_elements_kind);
    {
      // Smi handlers should only be installed for supported elements kinds.
      // Crash if we get here.
      DebugBreak();
      Goto(miss);
    }

    BIND(&if_oob);
    {
      Comment("out of bounds elements access");
      Label return_undefined(this);

      // Check if we're allowed to handle OOB accesses.
      TNode<BoolT> allow_out_of_bounds =
          IsSetWord32<LoadHandler::AllowOutOfBoundsBits>(handler_word);
      GotoIfNot(allow_out_of_bounds, miss);

      // Negative indices aren't valid array indices (according to
      // the ECMAScript specification), and are stored as properties
      // in V8, not elements. So we cannot handle them here, except
      // in case of typed arrays, where integer indexed properties
      // aren't looked up in the prototype chain.
      GotoIf(IsJSTypedArray(CAST(holder)), &return_undefined);
      if (Is64()) {
        GotoIfNot(
            UintPtrLessThanOrEqual(var_intptr_index.value(),
                                   IntPtrConstant(JSObject::kMaxElementIndex)),
            miss);
      } else {
        GotoIf(IntPtrLessThan(var_intptr_index.value(), IntPtrConstant(0)),
               miss);
      }

      // For all other receivers we need to check that the prototype chain
      // doesn't contain any elements.
      BranchIfPrototypesHaveNoElements(LoadMap(CAST(holder)), &return_undefined,
                                       miss);

      BIND(&return_undefined);
      exit_point->Return(access_mode == LoadAccessMode::kHas
                             ? TNode<Object>(FalseConstant())
                             : TNode<Object>(UndefinedConstant()));
    }

    BIND(&if_hole);
    {
      Comment("read hole and convert to undefined");

      GotoIfNot(IsSetWord32<LoadHandler::AllowHandlingHole>(handler_word),
                miss);
      GotoIf(IsNoElementsProtectorCellInvalid(), miss);
      exit_point->Return(access_mode == LoadAccessMode::kHas
                             ? TNode<Object>(FalseConstant())
                             : TNode<Object>(UndefinedConstant()));
    }

    if (access_mode != LoadAccessMode::kHas) {
      BIND(&if_indexed_string);
      {
        Label if_oob_string(this, Label::kDeferred);

        Comment("indexed string");
        TNode<String> string_holder = CAST(holder);
        TNode<IntPtrT> index = TryToIntptr(p->name(), miss);
        TNode<UintPtrT> length =
            Unsigned(LoadStringLengthAsWord(string_holder));
        GotoIf(UintPtrGreaterThanOrEqual(index, length), &if_oob_string);
        TNode<Int32T> code = StringCharCodeAt(string_holder, Unsigned(index));
        TNode<String> result = StringFromSingleCharCode(code);
        Return(result);

        BIND(&if_oob_string);
        if (Is64()) {
          // Indices >= 4294967295 are stored as named properties; handle them
          // in the runtime.
          GotoIfNot(UintPtrLessThanOrEqual(
                        index, IntPtrConstant(JSObject::kMaxElementIndex)),
                    miss);
        } else {
          GotoIf(IntPtrLessThan(index, IntPtrConstant(0)), miss);
        }
        TNode<BoolT> allow_out_of_bounds =
            IsSetWord32<LoadHandler::AllowOutOfBoundsBits>(handler_word);
        GotoIfNot(allow_out_of_bounds, miss);
        GotoIf(IsNoElementsProtectorCellInvalid(), miss);
        Return(UndefinedConstant());
      }
    }

    BIND(&if_property);
    Comment("property_load");
  }

  if (access_mode == LoadAccessMode::kHas) {
    HandleLoadICSmiHandlerHasNamedCase(p, holder, handler_kind, miss,
                                       exit_point, ic_mode);
  } else {
    HandleLoadICSmiHandlerLoadNamedCase(
        p, holder, handler_kind, handler_word, &rebox_double, &var_double_value,
        handler, miss, exit_point, ic_mode, on_nonexistent, support_elements);
  }
}

void AccessorAssembler::HandleLoadICSmiHandlerLoadNamedCase(
    const LazyLoadICParameters* p, TNode<Object> holder,
    TNode<Uint32T> handler_kind, TNode<Word32T> handler_word,
    Label* rebox_double, TVariable<Float64T>* var_double_value,
    TNode<MaybeObject> handler, Label* miss, ExitPoint* exit_point,
    ICMode ic_mode, OnNonExistent on_nonexistent,
    ElementSupport support_elements) {
  Label constant(this), field(this), normal(this, Label::kDeferred),
      slow(this, Label::kDeferred), interceptor(this, Label::kDeferred),
      nonexistent(this), accessor(this, Label::kDeferred),
      global(this, Label::kDeferred), module_export(this, Label::kDeferred),
      proxy(this, Label::kDeferred),
      native_data_property(this, Label::kDeferred),
      api_getter(this, Label::kDeferred);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kField)), &field);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kConstantFromPrototype)),
         &constant);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kNonExistent)), &nonexistent);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kNormal)), &normal);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kAccessorFromPrototype)),
         &accessor);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kNativeDataProperty)),
         &native_data_property);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kApiGetter)), &api_getter);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kApiGetterHolderIsPrototype)),
         &api_getter);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kGlobal)), &global);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kSlow)), &slow);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kProxy)), &proxy);

  Branch(Word32Equal(handler_kind, LOAD_KIND(kModuleExport)), &module_export,
         &interceptor);

  BIND(&field);
  {
#if V8_ENABLE_WEBASSEMBLY
    Label is_wasm_field(this);
    GotoIf(IsSetWord32<LoadHandler::IsWasmStructBits>(handler_word),
           &is_wasm_field);
#else
    CSA_DCHECK(this,
               IsClearWord32<LoadHandler::IsWasmStructBits>(handler_word));
#endif  // V8_ENABLE_WEBASSEMBLY

    HandleLoadField(CAST(holder), handler_word, var_double_value, rebox_double,
                    miss, exit_point);

#if V8_ENABLE_WEBASSEMBLY
    BIND(&is_wasm_field);
    HandleLoadWasmField(CAST(holder), handler_word, var_double_value,
                        rebox_double, exit_point);
#endif  // V8_ENABLE_WEBASSEMBLY
  }

  BIND(&nonexistent);
  // This is a handler for a load of a non-existent value.
  if (on_nonexistent == OnNonExistent::kThrowReferenceError) {
    exit_point->ReturnCallRuntime(Runtime::kThrowReferenceError, p->context(),
                                  p->name());
  } else {
    DCHECK_EQ(OnNonExistent::kReturnUndefined, on_nonexistent);
    exit_point->Return(UndefinedConstant());
  }

  BIND(&constant);
  {
    Comment("constant_load");
    exit_point->Return(holder);
  }

  BIND(&normal);
  {
    Comment("load_normal");
    TNode<PropertyDictionary> properties =
        CAST(LoadSlowProperties(CAST(holder)));
    TVARIABLE(IntPtrT, var_name_index);
    Label found(this, &var_name_index);
    NameDictionaryLookup<PropertyDictionary>(properties, CAST(p->name()),
                                             &found, &var_name_index, miss);
    BIND(&found);
    {
      TVARIABLE(Uint32T, var_details);
      TVARIABLE(Object, var_value);
      LoadPropertyFromDictionary<PropertyDictionary>(
          properties, var_name_index.value(), &var_details, &var_value);
      TNode<Object> value = CallGetterIfAccessor(
          var_value.value(), CAST(holder), var_details.value(), p->context(),
          p->receiver(), p->name(), miss);
      exit_point->Return(value);
    }
  }

  BIND(&accessor);
  {
    Comment("accessor_load");
    // The "holder" slot (data1) in the from-prototype LoadHandler is instead
    // directly the getter function.
    TNode<HeapObject> getter = CAST(holder);
    CSA_DCHECK(this, IsCallable(getter));

    exit_point->Return(Call(p->context(), getter, p->receiver()));
  }

  BIND(&native_data_property);
  HandleLoadCallbackProperty(p, CAST(holder), handler_word, exit_point);

  BIND(&api_getter);
  {
    if (p->receiver() != p->lookup_start_object()) {
      // Force super ICs using API getters into the slow path, so that we get
      // the correct receiver checks.
      Goto(&slow);
    } else {
      HandleLoadAccessor(p, CAST(holder), handler_word, CAST(handler),
                         handler_kind, exit_point);
    }
  }

  BIND(&proxy);
  {
    // TODO(mythria): LoadGlobals don't use this path. LoadGlobals need special
    // handling with proxies which is currently not supported by builtins. So
    // for such cases, we should install a slow path and never reach here. Fix
    // it to not generate this for LoadGlobals.
    CSA_DCHECK(this,
               WordNotEqual(IntPtrConstant(static_cast<int>(on_nonexistent)),
                            IntPtrConstant(static_cast<int>(
                                OnNonExistent::kThrowReferenceError))));
    TVARIABLE(IntPtrT, var_index);
    TVARIABLE(Name, var_unique);

    Label if_index(this), if_unique_name(this),
        to_name_failed(this, Label::kDeferred);

    if (support_elements == kSupportElements) {
      DCHECK_NE(on_nonexistent, OnNonExistent::kThrowReferenceError);

      TryToName(p->name(), &if_index, &var_index, &if_unique_name, &var_unique,
                &to_name_failed);

      BIND(&if_unique_name);
      exit_point->ReturnCallBuiltin(Builtin::kProxyGetProperty, p->context(),
                                    holder, var_unique.value(), p->receiver(),
                                    SmiConstant(on_nonexistent));

      BIND(&if_index);
      // TODO(mslekova): introduce TryToName that doesn't try to compute
      // the intptr index value
      Goto(&to_name_failed);

      BIND(&to_name_failed);
      // TODO(duongn): use GetPropertyWithReceiver builtin once
      // |lookup_element_in_holder| supports elements.
      exit_point->ReturnCallRuntime(Runtime::kGetPropertyWithReceiver,
                                    p->context(), holder, p->name(),
                                    p->receiver(), SmiConstant(on_nonexistent));
    } else {
      exit_point->ReturnCallBuiltin(Builtin::kProxyGetProperty, p->context(),
                                    holder, p->name(), p->receiver(),
                                    SmiConstant(on_nonexistent));
    }
  }

  BIND(&global);
  {
    CSA_DCHECK(this, IsPropertyCell(CAST(holder)));
    // Ensure the property cell doesn't contain the hole.
    TNode<Object> value =
        LoadObjectField(CAST(holder), PropertyCell::kValueOffset);
    TNode<Uint32T> details = Unsigned(LoadAndUntagToWord32ObjectField(
        CAST(holder), PropertyCell::kPropertyDetailsRawOffset));
    GotoIf(IsPropertyCellHole(value), miss);

    exit_point->Return(CallGetterIfAccessor(value, CAST(holder), details,
                                            p->context(), p->receiver(),
                                            p->name(), miss));
  }

  BIND(&interceptor);
  {
    Comment("load_interceptor");
    exit_point->ReturnCallRuntime(Runtime::kLoadPropertyWithInterceptor,
                                  p->context(), p->name(), p->receiver(),
                                  holder, p->slot(), p->vector());
  }
  BIND(&slow);
  {
    Comment("load_slow");
    if (ic_mode == ICMode::kGlobalIC) {
      exit_point->ReturnCallRuntime(Runtime::kLoadGlobalIC_Slow, p->context(),
                                    p->name(), p->slot(), p->vector());

    } else {
      exit_point->ReturnCallRuntime(Runtime::kGetProperty, p->context(),
                                    p->lookup_start_object(), p->name(),
                                    p->receiver());
    }
  }

  BIND(&module_export);
  {
    Comment("module export");
    TNode<UintPtrT> index =
        DecodeWordFromWord32<LoadHandler::ExportsIndexBits>(handler_word);
    TNode<Module> module =
        LoadObjectField<Module>(CAST(holder), JSModuleNamespace::kModuleOffset);
    TNode<ObjectHashTable> exports =
        LoadObjectField<ObjectHashTable>(module, Module::kExportsOffset);
    TNode<Cell> cell = CAST(LoadFixedArrayElement(exports, index));
    // The handler is only installed for exports that exist.
    TNode<Object> value = LoadCellValue(cell);
    Label is_the_hole(this, Label::kDeferred);
    GotoIf(IsTheHole(value), &is_the_hole);
    exit_point->Return(value);

    BIND(&is_the_hole);
    {
      TNode<Smi> message = SmiConstant(MessageTemplate::kNotDefined);
      exit_point->ReturnCallRuntime(Runtime::kThrowReferenceError, p->context(),
                                    message, p->name());
    }
  }

  BIND(rebox_double);
  exit_point->Return(AllocateHeapNumberWithValue(var_double_value->value()));
}

void AccessorAssembler::HandleLoadICSmiHandlerHasNamedCase(
    const LazyLoadICParameters* p, TNode<Object> holder,
    TNode<Uint32T> handler_kind, Label* miss, ExitPoint* exit_point,
    ICMode ic_mode) {
  Label return_true(this), return_false(this), return_lookup(this),
      normal(this), global(this), slow(this);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kField)), &return_true);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kConstantFromPrototype)),
         &return_true);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kNonExistent)), &return_false);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kNormal)), &normal);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kAccessorFromPrototype)),
         &return_true);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kNativeDataProperty)),
         &return_true);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kApiGetter)), &return_true);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kApiGetterHolderIsPrototype)),
         &return_true);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kSlow)), &slow);

  Branch(Word32Equal(handler_kind, LOAD_KIND(kGlobal)), &global,
         &return_lookup);

  BIND(&return_true);
  exit_point->Return(TrueConstant());

  BIND(&return_false);
  exit_point->Return(FalseConstant());

  BIND(&return_lookup);
  {
    CSA_DCHECK(this,
               Word32Or(Word32Equal(handler_kind, LOAD_KIND(kInterceptor)),
                        Word32Or(Word32Equal(handler_kind, LOAD_KIND(kProxy)),
                                 Word32Equal(handler_kind,
                                             LOAD_KIND(kModuleExport)))));
    exit_point->ReturnCallBuiltin(Builtin::kHasProperty, p->context(),
                                  p->receiver(), p->name());
  }

  BIND(&normal);
  {
    Comment("has_normal");
    TNode<PropertyDictionary> properties =
        CAST(LoadSlowProperties(CAST(holder)));
    TVARIABLE(IntPtrT, var_name_index);
    Label found(this);
    NameDictionaryLookup<PropertyDictionary>(properties, CAST(p->name()),
                                             &found, &var_name_index, miss);

    BIND(&found);
    exit_point->Return(TrueConstant());
  }

  BIND(&global);
  {
    CSA_DCHECK(this, IsPropertyCell(CAST(holder)));
    // Ensure the property cell doesn't contain the hole.
    TNode<Object> value =
        LoadObjectField(CAST(holder), PropertyCell::kValueOffset);
    GotoIf(IsPropertyCellHole(value), miss);

    exit_point->Return(TrueConstant());
  }

  BIND(&slow);
  {
    Comment("load_slow");
    if (ic_mode == ICMode::kGlobalIC) {
      exit_point->ReturnCallRuntime(Runtime::kLoadGlobalIC_Slow, p->context(),
                                    p->name(), p->slot(), p->vector());
    } else {
      exit_point->ReturnCallRuntime(Runtime::kHasProperty, p->context(),
                                    p->receiver(), p->name());
    }
  }
}

// Performs actions common to both load and store handlers:
// 1. Checks prototype validity cell.
// 2. If |on_code_handler| is provided, then it checks if the sub handler is
//    a smi or code and if it's a code then it calls |on_code_handler| to
//    generate a code that handles Code handlers.
//    If |on_code_handler| is not provided, then only smi sub handler are
//    expected.
// 3. Does access check on lookup start object if
//    ICHandler::DoAccessCheckOnLookupStartObjectBits bit is set in the smi
//    handler.
// 4. Does dictionary lookup on receiver if
//    ICHandler::LookupOnLookupStartObjectBits bit is set in the smi handler. If
//    |on_found_on_lookup_start_object| is provided then it calls it to
//    generate a code that handles the "found on receiver case" or just misses
//    if the |on_found_on_lookup_start_object| is not provided.
// 5. Falls through in a case of a smi handler which is returned from this
//    function (tagged!).
// TODO(ishell): Remove templatezation once we move common bits from
// Load/StoreHandler to the base class.
template <typename ICHandler, typename ICParameters>
TNode<Object> AccessorAssembler::HandleProtoHandler(
    const ICParameters* p, TNode<DataHandler> handler,
    const OnCodeHandler& on_code_handler,
    const OnFoundOnLookupStartObject& on_found_on_lookup_start_object,
    Label* miss, ICMode ic_mode) {
  //
  // Check prototype validity cell.
  //
  {
    TNode<Object> maybe_validity_cell =
        LoadObjectField(handler, ICHandler::kValidityCellOffset);
    CheckPrototypeValidityCell(maybe_validity_cell, miss);
  }

  //
  // Check smi handler bits.
  //
  {
    TNode<Object> smi_or_code_handler =
        LoadObjectField(handler, ICHandler::kSmiHandlerOffset);
    if (on_code_handler) {
      Label if_smi_handler(this);
      GotoIf(TaggedIsSmi(smi_or_code_handler), &if_smi_handler);
      TNode<Code> code = CAST(smi_or_code_handler);
      on_code_handler(code);

      BIND(&if_smi_handler);
    }
    TNode<IntPtrT> handler_flags = SmiUntag(CAST(smi_or_code_handler));

    // Lookup on receiver and access checks are not necessary for global ICs
    // because in the former case the validity cell check guards modifications
    // of the global object and the latter is not applicable to the global
    // object.
    int mask = ICHandler::LookupOnLookupStartObjectBits::kMask |
               ICHandler::DoAccessCheckOnLookupStartObjectBits::kMask;
    if (ic_mode == ICMode::kGlobalIC) {
      CSA_DCHECK(this, IsClearWord(handler_flags, mask));
    } else {
      DCHECK_EQ(ICMode::kNonGlobalIC, ic_mode);

      Label done(this), if_do_access_check(this),
          if_lookup_on_lookup_start_object(this);
      GotoIf(IsClearWord(handler_flags, mask), &done);
      // Only one of the bits can be set at a time.
      CSA_DCHECK(this,
                 WordNotEqual(WordAnd(handler_flags, IntPtrConstant(mask)),
                              IntPtrConstant(mask)));
      Branch(
          IsSetWord<typename ICHandler::DoAccessCheckOnLookupStartObjectBits>(
              handler_flags),
          &if_do_access_check, &if_lookup_on_lookup_start_object);

      BIND(&if_do_access_check);
      {
        TNode<MaybeObject> data2 = LoadHandlerDataField(handler, 2);
        CSA_DCHECK(this, IsWeakOrCleared(data2));
        TNode<Context> expected_native_context =
            CAST(GetHeapObjectAssumeWeak(data2, miss));
        EmitAccessCheck(expected_native_context, p->context(),
                        p->lookup_start_object(), &done, miss);
      }

      BIND(&if_lookup_on_lookup_start_object);
      {
        // Dictionary lookup on lookup start object is not necessary for
        // Load/StoreGlobalIC (which is the only case when the
        // lookup_start_object can be a JSGlobalObject) because prototype
        // validity cell check already guards modifications of the global
        // object.
        CSA_DCHECK(this,
                   Word32BinaryNot(HasInstanceType(
                       CAST(p->lookup_start_object()), JS_GLOBAL_OBJECT_TYPE)));

        TNode<PropertyDictionary> properties =
            CAST(LoadSlowProperties(CAST(p->lookup_start_object())));
        TVARIABLE(IntPtrT, var_name_index);
        Label found(this, &var_name_index);
        NameDictionaryLookup<PropertyDictionary>(
            properties, CAST(p->name()), &found, &var_name_index, &done);
        BIND(&found);
        {
          if (on_found_on_lookup_start_object) {
            on_found_on_lookup_start_object(properties, var_name_index.value());
          } else {
            Goto(miss);
          }
        }
      }

      BIND(&done);
    }
    return smi_or_code_handler;
  }
}

void AccessorAssembler::HandleLoadICProtoHandler(
    const LazyLoadICParameters* p, TNode<DataHandler> handler,
    TVariable<Object>* var_holder, TVariable<MaybeObject>* var_smi_handler,
    Label* if_smi_handler, Label* miss, ExitPoint* exit_point, ICMode ic_mode,
    LoadAccessMode access_mode) {
  TNode<Smi> smi_handler = CAST(HandleProtoHandler<LoadHandler>(
      p, handler,
      // Code sub-handlers are not expected in LoadICs, so no |on_code_handler|.
      nullptr,
      // on_found_on_lookup_start_object
      [=, this](TNode<PropertyDictionary> properties,
                TNode<IntPtrT> name_index) {
        if (access_mode == LoadAccessMode::kHas) {
          exit_point->Return(TrueConstant());
        } else {
          TVARIABLE(Uint32T, var_details);
          TVARIABLE(Object, var_value);
          LoadPropertyFromDictionary<PropertyDictionary>(
              properties, name_index, &var_details, &var_value);
          TNode<Object> value = CallGetterIfAccessor(
              var_value.value(), CAST(var_holder->value()), var_details.value(),
              p->context(), p->receiver(), p->name(), miss);
          exit_point->Return(value);
        }
      },
      miss, ic_mode));

  TNode<MaybeObject> maybe_holder_or_constant =
      LoadHandlerDataField(handler, 1);

  Label load_from_cached_holder(this), is_smi(this), done(this);

  GotoIf(TaggedIsSmi(maybe_holder_or_constant), &is_smi);
  Branch(TaggedEqual(maybe_holder_or_constant, NullConstant()), &done,
         &load_from_cached_holder);

  BIND(&is_smi);
  {
    // If the "maybe_holder_or_constant" in the handler is a smi, then it's
    // guaranteed that it's not a holder object, but a constant value.
    CSA_DCHECK(this, Word32Equal(DecodeWord32<LoadHandler::KindBits>(
                                     SmiToInt32(smi_handler)),
                                 LOAD_KIND(kConstantFromPrototype)));
    if (access_mode == LoadAccessMode::kHas) {
      exit_point->Return(TrueConstant());
    } else {
      exit_point->Return(CAST(maybe_holder_or_constant));
    }
  }

  BIND(&load_from_cached_holder);
  {
    // For regular holders, having passed the receiver map check and
    // the validity cell check implies that |holder| is
    // alive. However, for global object receivers, |maybe_holder| may
    // be cleared.
    CSA_DCHECK(this, IsWeakOrCleared(maybe_holder_or_constant));
    TNode<HeapObject> holder =
        GetHeapObjectAssumeWeak(maybe_holder_or_constant, miss);
    *var_holder = holder;
    Goto(&done);
  }

  BIND(&done);
  {
    *var_smi_handler = smi_handler;
    Goto(if_smi_handler);
  }
}

void AccessorAssembler::EmitAccessCheck(TNode<Context> expected_native_context,
                                        TNode<Context> context,
                                        TNode<Object> receiver,
                                        Label* can_access, Label* miss) {
  CSA_DCHECK(this, IsNativeContext(expected_native_context));

  TNode<NativeContext> native_context = LoadNativeContext(context);
  GotoIf(TaggedEqual(expected_native_context, native_context), can_access);
  // If the receiver is not a JSGlobalProxy then we miss.
  GotoIf(TaggedIsSmi(receiver), miss);
  GotoIfNot(IsJSGlobalProxy(CAST(receiver)), miss);
  // For JSGlobalProxy receiver try to compare security tokens of current
  // and expected native contexts.
  TNode<Object> expected_token = LoadContextElement(
      expected_native_context, Context::SECURITY_TOKEN_INDEX);
  TNode<Object> current_token =
      LoadContextElement(native_context, Context::SECURITY_TOKEN_INDEX);
  Branch(TaggedEqual(expected_token, current_token), can_access, miss);
}

void AccessorAssembler::JumpIfDataProperty(TNode<Uint32T> details,
                                           Label* writable, Label* readonly) {
  if (readonly) {
    // Accessor properties never have the READ_ONLY attribute set.
    GotoIf(IsSetWord32(details, PropertyDetails::kAttributesReadOnlyMask),
           readonly);
  } else {
    CSA_DCHECK(this, IsNotSetWord32(details,
                                    PropertyDetails::kAttributesReadOnlyMask));
  }
  TNode<Uint32T> kind = DecodeWord32<PropertyDetails::KindField>(details);
  GotoIf(
      Word32Equal(kind, Int32Constant(static_cast<int>(PropertyKind::kData))),
      writable);
  // Fall through if it's an accessor property.
}

void AccessorAssembler::HandleStoreICNativeDataProperty(
    const StoreICParameters* p, TNode<HeapObject> holder,
    TNode<Word32T> handler_word) {
  Comment("native_data_property_store");
  TNode<IntPtrT> descriptor =
      Signed(DecodeWordFromWord32<StoreHandler::DescriptorBits>(handler_word));
  TNode<AccessorInfo> accessor_info =
      CAST(LoadDescriptorValue(LoadMap(holder), descriptor));

  TailCallRuntime(Runtime::kStoreCallbackProperty, p->context(), p->receiver(),
                  holder, accessor_info, p->name(), p->value());
}

void AccessorAssembler::HandleStoreICSmiHandlerJSSharedStructFieldCase(
    TNode<Context> context, TNode<Word32T> handler_word, TNode<JSObject> holder,
    TNode<Object> value) {
  CSA_DCHECK(this,
             Word32Equal(DecodeWord32<StoreHandler::KindBits>(handler_word),
                         STORE_KIND(kSharedStructField)));
  CSA_DCHECK(
      this,
      Word32Equal(DecodeWord32<StoreHandler::RepresentationBits>(handler_word),
                  Int32Constant(Representation::kTagged)));

  TVARIABLE(Object, shared_value, value);
  SharedValueBarrier(context, &shared_value);

  TNode<BoolT> is_inobject =
      IsSetWord32<StoreHandler::IsInobjectBits>(handler_word);
  TNode<HeapObject> property_storage = Select<HeapObject>(
      is_inobject, [&]() { return holder; },
      [&]() { return LoadFastProperties(holder, true); });

  TNode<UintPtrT> index =
      DecodeWordFromWord32<StoreHandler::FieldIndexBits>(handler_word);
  TNode<IntPtrT> offset = Signed(TimesTaggedSize(index));

  StoreSharedObjectField(property_storage, offset, shared_value.value());

  // Return the original value.
  Return(value);
}

void AccessorAssembler::HandleStoreICHandlerCase(
    const StoreICParameters* p, TNode<MaybeObject> handler, Label* miss,
    ICMode ic_mode, ElementSupport support_elements) {
  Label if_smi_handler(this), if_nonsmi_handler(this);
  Label if_proto_handler(this), call_handler(this),
      store_transition_or_global_or_accessor(this);

  Branch(TaggedIsSmi(handler), &if_smi_handler, &if_nonsmi_handler);

  Label if_slow(this);

  // |handler| is a Smi, encoding what to do. See SmiHandler methods
  // for the encoding format.
  BIND(&if_smi_handler);
  {
    TNode<Object> holder = p->receiver();
    TNode<Int32T> handler_word = SmiToInt32(CAST(handler));

    Label if_fast_smi(this), if_proxy(this), if_interceptor(this);

#define ASSERT_CONSECUTIVE(a, b)                                    \
  static_assert(static_cast<intptr_t>(StoreHandler::Kind::a) + 1 == \
                static_cast<intptr_t>(StoreHandler::Kind::b));
    ASSERT_CONSECUTIVE(kGlobalProxy, kNormal)
    ASSERT_CONSECUTIVE(kNormal, kInterceptor)
    ASSERT_CONSECUTIVE(kInterceptor, kSlow)
    ASSERT_CONSECUTIVE(kSlow, kProxy)
    ASSERT_CONSECUTIVE(kProxy, kKindsNumber)
#undef ASSERT_CONSECUTIVE

    TNode<Uint32T> handler_kind =
        DecodeWord32<StoreHandler::KindBits>(handler_word);
    GotoIf(Int32LessThan(handler_kind, STORE_KIND(kGlobalProxy)), &if_fast_smi);
    GotoIf(Word32Equal(handler_kind, STORE_KIND(kProxy)), &if_proxy);
    GotoIf(Word32Equal(handler_kind, STORE_KIND(kInterceptor)),
           &if_interceptor);
    GotoIf(Word32Equal(handler_kind, STORE_KIND(kSlow)), &if_slow);
    CSA_DCHECK(this, Word32Equal(handler_kind, STORE_KIND(kNormal)));
    TNode<PropertyDictionary> properties =
        CAST(LoadSlowProperties(CAST(holder)));

    TVARIABLE(IntPtrT, var_name_index);
    Label dictionary_found(this, &var_name_index);
    if (p->IsAnyDefineOwn()) {
      NameDictionaryLookup<PropertyDictionary>(properties, CAST(p->name()),
                                               &if_slow, nullptr, miss);
    } else {
      NameDictionaryLookup<PropertyDictionary>(properties, CAST(p->name()),
                                               &dictionary_found,
                                               &var_name_index, miss);
    }

    // When dealing with class fields defined with DefineKeyedOwnIC or
    // DefineNamedOwnIC, use the slow path to check the existing property.
    if (!p->IsAnyDefineOwn()) {
      BIND(&dictionary_found);
      {
        Label if_constant(this), done(this);
        TNode<Uint32T> details =
            LoadDetailsByKeyIndex(properties, var_name_index.value());
        // Check that the property is a writable data property (no accessor).
        const int kTypeAndReadOnlyMask =
            PropertyDetails::KindField::kMask |
            PropertyDetails::kAttributesReadOnlyMask;
        static_assert(static_cast<int>(PropertyKind::kData) == 0);
        GotoIf(IsSetWord32(details, kTypeAndReadOnlyMask), miss);

        if (V8_DICT_PROPERTY_CONST_TRACKING_BOOL) {
          GotoIf(IsPropertyDetailsConst(details), miss);
        }

        StoreValueByKeyIndex<PropertyDictionary>(
            properties, var_name_index.value(), p->value());
        Return(p->value());
      }
    }
    BIND(&if_fast_smi);
    {
      Label data(this), shared_struct_field(this), native_data_property(this);
      GotoIf(Word32Equal(handler_kind, STORE_KIND(kNativeDataProperty)),
             &native_data_property);
      Branch(Word32Equal(handler_kind, STORE_KIND(kSharedStructField)),
             &shared_struct_field, &data);

      BIND(&native_data_property);
      HandleStoreICNativeDataProperty(p, CAST(holder), handler_word);

      BIND(&shared_struct_field);
      HandleStoreICSmiHandlerJSSharedStructFieldCase(p->context(), handler_word,
                                                     CAST(holder), p->value());

      BIND(&data);
      // Handle non-transitioning field stores.
      HandleStoreICSmiHandlerCase(handler_word, CAST(holder), p->value(), miss);
    }

    BIND(&if_proxy);
    {
      CSA_DCHECK(this, BoolConstant(!p->IsDefineKeyedOwn()));
      HandleStoreToProxy(p, CAST(holder), miss, support_elements);
    }

    BIND(&if_interceptor);
    {
      Comment("store_interceptor");
      TailCallRuntime(Runtime::kStorePropertyWithInterceptor, p->context(),
                      p->value(), p->receiver(), p->name());
    }

    BIND(&if_slow);
    {
      Comment("store_slow");
      // The slow case calls into the runtime to complete the store without
      // causing an IC miss that would otherwise cause a transition to the
      // generic stub.
      if (ic_mode == ICMode::kGlobalIC) {
        TailCallRuntime(Runtime::kStoreGlobalIC_Slow, p->context(), p->value(),
                        p->slot(), p->vector(), p->receiver(), p->name());
      } else {
        Runtime::FunctionId id;
        if (p->IsDefineNamedOwn()) {
          id = Runtime::kDefineNamedOwnIC_Slow;
        } else if (p->IsDefineKeyedOwn()) {
          id = Runtime::kDefineKeyedOwnIC_Slow;
        } else {
          id = Runtime::kKeyedStoreIC_Slow;
        }
        TailCallRuntime(id, p->context(), p->value(), p->receiver(), p->name());
      }
    }
  }

  BIND(&if_nonsmi_handler);
  {
    TNode<HeapObjectReference> ref_handler = CAST(handler);
    GotoIf(IsWeakOrCleared(ref_handler),
           &store_transition_or_global_or_accessor);
    TNode<HeapObject> strong_handler = CAST(handler);
    TNode<Map> handler_map = LoadMap(strong_handler);
    Branch(IsCodeMap(handler_map), &call_handler, &if_proto_handler);

    BIND(&if_proto_handler);
    {
      // Note, although DefineOwnICs don't reqiure checking for prototype
      // chain modifications the proto handlers shape is still used for
      // StoreHandler::StoreElementTransition in order to store both Code
      // handler and transition target map.
      HandleStoreICProtoHandler(p, CAST(strong_handler), &if_slow, miss,
                                ic_mode, support_elements);
    }

    // |handler| is a heap object. Must be code, call it.
    BIND(&call_handler);
    {
      TNode<Code> code_handler = CAST(strong_handler);
      TailCallStub(StoreWithVectorDescriptor{}, code_handler, p->context(),
                   p->receiver(), p->name(), p->value(), p->slot(),
                   p->vector());
    }
  }

  BIND(&store_transition_or_global_or_accessor);
  {
    // Load value or miss if the {handler} weak cell is cleared.
    CSA_DCHECK(this, IsWeakOrCleared(handler));
    TNode<HeapObject> strong_handler = GetHeapObjectAssumeWeak(handler, miss);

    Label store_global(this), store_transition(this), store_accessor(this);
    TNode<Map> strong_handler_map = LoadMap(strong_handler);
    GotoIf(IsPropertyCellMap(strong_handler_map), &store_global);
    Branch(IsAccessorPairMap(strong_handler_map), &store_accessor,
           &store_transition);

    BIND(&store_global);
    {
      if (p->IsDefineKeyedOwn()) {
        Label proceed_defining(this);
        // StoreGlobalIC_PropertyCellCase doesn't support definition
        // of private fields, so handle them in runtime.
        GotoIfNot(IsSymbol(CAST(p->name())), &proceed_defining);
        Branch(IsPrivateName(CAST(p->name())), &if_slow, &proceed_defining);
        BIND(&proceed_defining);
      }

      TNode<PropertyCell> property_cell = CAST(strong_handler);
      ExitPoint direct_exit(this);
      StoreGlobalIC_PropertyCellCase(property_cell, p->value(), &direct_exit,
                                     miss);
    }
    BIND(&store_accessor);
    {
      TNode<AccessorPair> pair = CAST(strong_handler);
      TNode<JSFunction> setter = CAST(LoadAccessorPairSetter(pair));
      // As long as this code path is not used for StoreSuperIC the receiver
      // is known to be neither undefined nor null.
      ConvertReceiverMode mode = ConvertReceiverMode::kNotNullOrUndefined;
      Return(
          CallFunction(p->context(), setter, mode, p->receiver(), p->value()));
    }
    BIND(&store_transition);
    {
      TNode<Map> map = CAST(strong_handler);
      HandleStoreICTransitionMapHandlerCase(p, map, miss,
                                            p->IsAnyDefineOwn()
                                                ? kDontCheckPrototypeValidity
                                                : kCheckPrototypeValidity);
      Return(p->value());
    }
  }
}

void AccessorAssembler::HandleStoreICTransitionMapHandlerCase(
    const StoreICParameters* p, TNode<Map> transition_map, Label* miss,
    StoreTransitionMapFlags flags) {
  DCHECK_EQ(0, flags & ~kStoreTransitionMapFlagsMask);
  if (flags & kCheckPrototypeValidity) {
    TNode<Object> maybe_validity_cell =
        LoadObjectField(transition_map, Map::kPrototypeValidityCellOffset);
    CheckPrototypeValidityCell(maybe_validity_cell, miss);
  }

  TNode<Uint32T> bitfield3 = LoadMapBitField3(transition_map);
  CSA_DCHECK(this, IsClearWord32<Map::Bits3::IsDictionaryMapBit>(bitfield3));
  GotoIf(IsSetWord32<Map::Bits3::IsDeprecatedBit>(bitfield3), miss);

  // Load last descriptor details.
  TNode<UintPtrT> nof =
      DecodeWordFromWord32<Map::Bits3::NumberOfOwnDescriptorsBits>(bitfield3);
  CSA_DCHECK(this, WordNotEqual(nof, IntPtrConstant(0)));
  TNode<DescriptorArray> descriptors = LoadMapDescriptors(transition_map);

  TNode<IntPtrT> factor = IntPtrConstant(DescriptorArray::kEntrySize);
  TNode<IntPtrT> last_key_index = UncheckedCast<IntPtrT>(IntPtrAdd(
      IntPtrConstant(DescriptorArray::ToKeyIndex(-1)), IntPtrMul(nof, factor)));
  if (flags & kValidateTransitionHandler) {
    TNode<Name> key = LoadKeyByKeyIndex(descriptors, last_key_index);
    GotoIf(TaggedNotEqual(key, p->name()), miss);
  } else {
    CSA_DCHECK(this, TaggedEqual(LoadKeyByKeyIndex(descriptors, last_key_index),
                                 p->name()));
  }
  TNode<Uint32T> details = LoadDetailsByKeyIndex(descriptors, last_key_index);
  if (flags & kValidateTransitionHandler) {
    // Follow transitions only in the following cases:
    // 1) name is a non-private symbol and attributes equal to NONE,
    // 2) name is a private symbol and attributes equal to DONT_ENUM.
    Label attributes_ok(this);
    const int kKindAndAttributesDontDeleteReadOnlyMask =
        PropertyDetails::KindField::kMask |
        PropertyDetails::kAttributesDontDeleteMask |
        PropertyDetails::kAttributesReadOnlyMask;
    static_assert(static_cast<int>(PropertyKind::kData) == 0);
    // Both DontDelete and ReadOnly attributes must not be set and it has to be
    // a kData property.
    GotoIf(IsSetWord32(details, kKindAndAttributesDontDeleteReadOnlyMask),
           miss);

    // DontEnum attribute is allowed only for private symbols and vice versa.
    Branch(Word32Equal(
               IsSetWord32(details, PropertyDetails::kAttributesDontEnumMask),
               IsPrivateSymbol(CAST(p->name()))),
           &attributes_ok, miss);

    BIND(&attributes_ok);
  }

  OverwriteExistingFastDataProperty(CAST(p->receiver()), transition_map,
                                    descriptors, last_key_index, details,
                                    p->value(), miss, true);
}

void AccessorAssembler::UpdateMayHaveInterestingProperty(
    TNode<PropertyDictionary> dict, TNode<Name> name) {
  Comment("UpdateMayHaveInterestingProperty");
  Label done(this);

  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    // TODO(pthier): Add flags to swiss dictionaries.
    Goto(&done);
  } else {
    GotoIfNot(IsInterestingProperty(name), &done);
    TNode<Smi> flags = GetNameDictionaryFlags(dict);
    flags = SmiOr(
        flags,
        SmiConstant(
            NameDictionary::MayHaveInterestingPropertiesBit::encode(true)));
    SetNameDictionaryFlags(dict, flags);
    Goto(&done);
  }
  BIND(&done);
}

void AccessorAssembler::CheckFieldType(TNode<DescriptorArray> descriptors,
                                       TNode<IntPtrT> name_index,
                                       TNode<Word32T> representation,
                                       TNode<Object> value, Label* bailout) {
  Label r_smi(this), r_double(this), r_heapobject(this), all_fine(this);
  GotoIf(Word32Equal(representation, Int32Constant(Representation::kSmi)),
         &r_smi);
  GotoIf(Word32Equal(representation, Int32Constant(Representation::kDouble)),
         &r_double);
  GotoIf(
      Word32Equal(representation, Int32Constant(Representation::kHeapObject)),
      &r_heapobject);
  GotoIf(Word32Equal(representation, Int32Constant(Representation::kNone)),
         bailout);
  CSA_DCHECK(this, Word32Equal(representation,
                               Int32Constant(Representation::kTagged)));
  Goto(&all_fine);

  BIND(&r_smi);
  { Branch(TaggedIsSmi(value), &all_fine, bailout); }

  BIND(&r_double);
  {
    GotoIf(TaggedIsSmi(value), &all_fine);
    Branch(IsHeapNumber(CAST(value)), &all_fine, bailout);
  }

  BIND(&r_heapobject);
  {
    GotoIf(TaggedIsSmi(value), bailout);
    TNode<MaybeObject> field_type =
        LoadFieldTypeByKeyIndex(descriptors, name_index);
    const Address kAnyType
```