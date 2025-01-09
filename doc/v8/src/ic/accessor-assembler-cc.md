Response:
My thought process to analyze the provided C++ code snippet goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the `accessor-assembler.cc` file within the V8 JavaScript engine. It also asks for connections to JavaScript functionality, examples, and common programming errors if applicable. The key here is "functional summary."

2. **Initial Scan and Keywords:** I quickly scanned the code for recognizable keywords and patterns. Things that jumped out:
    * `AccessorAssembler`: This is clearly a class name, likely the central focus.
    * `LoadHandler`, `StoreHandler`: These suggest the code deals with accessing and modifying object properties.
    * `TryMonomorphicCase`, `HandlePolymorphicCase`, `TryMegaDOMCase`: These indicate optimization strategies for property access. "Monomorphic" and "Polymorphic" are strong hints about inline caching (IC).
    * `FeedbackVector`, `WeakFixedArray`: These are IC-related data structures.
    * `HandleLoadIC...`, `HandleStoreIC...`:  Explicit mentions of Load and Store IC, further confirming the focus on property access.
    * `Builtin::kCallFunctionTemplate_Generic`, `Builtin::kCallApiGetter`: Calls to built-in functions, likely related to native code or API interactions.
    * `EnumCache`:  Related to iterating object properties (e.g., `for...in`).
    * `JSObject`, `Map`, `PropertyArray`: Core V8 object model concepts.
    * `WasmObject`:  Support for WebAssembly integration.
    * `ExitPoint`:  A mechanism for returning values or jumping to different parts of the generated code.
    * Macros like `LOAD_KIND`, `STORE_KIND`, `CSA_DCHECK`.

3. **Identify Core Functionality Areas:** Based on the keywords, I started to group related code blocks into logical functional areas:
    * **Handler Management:**  Functions like `LoadHandlerDataField` deal with accessing data within `LoadHandler` and `StoreHandler` objects.
    * **Inline Caching (IC):**  The `TryMonomorphicCase` and `HandlePolymorphicCase` clearly fall under IC optimization. The feedback vector interaction is a strong indicator.
    * **MegaDOM Handling:**  The `TryMegaDOMCase` function suggests specific handling for DOM objects, likely for performance reasons.
    * **Enumerated Property Access:**  `TryEnumeratedKeyedLoad` relates to how `for...in` loops access properties.
    * **Load IC Handling (General):** The `HandleLoadICHandlerCase` function seems to be a central dispatcher for different load scenarios.
    * **Specific Load Handlers:**  Functions like `HandleLoadCallbackProperty`, `HandleLoadAccessor`, `HandleLoadField`, and `HandleLoadWasmField` handle different types of property access (callbacks, accessors, regular fields, WebAssembly fields).
    * **Smi Handler Handling:**  `HandleLoadICSmiHandlerCase` and its sub-functions address optimizations where handler information is encoded in a Smi.

4. **Infer the Overall Purpose:** By observing these functional areas, I concluded that the primary goal of `accessor-assembler.cc` is to generate optimized code for accessing object properties (both reading and, based on the presence of `STORE_KIND`, potentially writing, though the provided snippet focuses on loads). It does this by implementing various optimization techniques like inline caching, handling special object types (like DOM objects), and dealing with different property kinds (fields, accessors, etc.).

5. **Connect to JavaScript:**  I started thinking about how these low-level operations relate to everyday JavaScript code.
    * **Property Access:** The most obvious connection is the `.` and `[]` operators used to access object properties.
    * **`for...in` loops:**  The `TryEnumeratedKeyedLoad` function directly corresponds to the behavior of these loops.
    * **Getters and Setters:**  The `HandleLoadAccessor` function is related to how JavaScript getters are invoked.
    * **DOM Interaction:**  `TryMegaDOMCase` is relevant when JavaScript interacts with the browser's Document Object Model.
    * **WebAssembly:** The `HandleLoadWasmField` functions are used when JavaScript interacts with WebAssembly modules.

6. **Develop JavaScript Examples:** For each connection to JavaScript, I created simple code snippets to illustrate the underlying mechanism handled by `accessor-assembler.cc`. The examples aim to be clear and directly related to the identified functionalities.

7. **Identify Potential Programming Errors:** I considered common JavaScript errors that might be related to property access. `TypeError` when accessing properties of `null` or `undefined`, and `ReferenceError` when trying to access non-existent variables (which can sometimes manifest as property access errors) seemed like the most relevant examples.

8. **Code Logic Reasoning (Hypothetical):**  I picked a simpler optimization case, the monomorphic load, and provided a hypothetical input (object and property) and explained the expected output (the property value) based on the code's logic. The goal was to show how the IC mechanism works in a simplified scenario.

9. **Address the `.tq` Question:**  I noted that the `.cc` extension indicates C++ code, not Torque (`.tq`).

10. **Structure the Output:**  Finally, I organized the findings into the requested sections: Functionality, JavaScript Connection, JavaScript Example, Code Logic Reasoning, Common Programming Errors, and a concise summary for Part 1. I used clear and concise language, avoiding overly technical jargon where possible.

**Self-Correction/Refinement during the process:**

* **Initial focus might have been too low-level:** I initially focused too much on the individual C++ details. I had to step back and think about the *purpose* of these details in the context of JavaScript.
* **Connecting IC to JavaScript:**  It's easy to talk about "monomorphic" and "polymorphic" in the context of IC, but it's crucial to explain *why* this matters for JavaScript performance (faster property access).
* **Choosing relevant JavaScript examples:**  I made sure the examples were simple and directly demonstrated the functionality being discussed. Avoided complex scenarios that might obscure the point.
* **Balancing technical detail with clarity:**  I tried to explain the C++ code's purpose without getting bogged down in the minutiae of every line of code. The goal was a *functional* summary, not a line-by-line explanation.
```cpp
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
  BIND(&type_
Prompt: 
```
这是目录为v8/src/ic/accessor-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/accessor-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共7部分，请归纳一下它的功能

"""
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
    Comment("const
"""


```