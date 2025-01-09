Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine.

Here's a breakdown of the request and how to address each point:

1. **List the functionalities:** I need to analyze the code and identify the key operations and logic it implements. This involves looking at the class `KeyedStoreGenericAssembler` and its methods.
2. **Check for Torque source:** I need to see if the filename ends in `.tq`. In this case, it ends in `.cc`, so it's not Torque.
3. **Relate to JavaScript:**  I need to determine how the C++ code connects to JavaScript features. The names of the methods and the comments within the code provide clues (e.g., `[[Set]]`, `[[CreateDataProperty]]`, `Object.fromEntries()`). I'll need to provide JavaScript examples that trigger these functionalities.
4. **Code logic reasoning (input/output):** This is tricky for such low-level code. I'll need to make reasonable assumptions about inputs (like the type of receiver, key, and value) and the expected behavior (like successfully storing a value or triggering a slow path).
5. **Common programming errors:** I need to think about typical mistakes JavaScript developers make that could lead to this specific code being executed (e.g., trying to write to a read-only property).
6. **Summarize the function (Part 1):**  I need to provide a concise overview of what the code is responsible for, based on the analysis.

**Mental Sandbox Simulation:**

* I see various `StoreMode` enums, suggesting different ways properties can be set.
* The `KeyedStoreGenericAssembler` class seems to be the core, handling different storage scenarios.
* Methods like `KeyedStoreGeneric`, `KeyedStoreMegamorphic`, and `StoreProperty` likely represent different optimization levels or entry points for property storage.
* The code deals with array-like properties (indexed access) and regular object properties.
* There's logic for handling different `ElementsKind` (like packed vs. holey arrays, SMI vs. double elements), which is related to V8's internal optimizations.
* The code also seems to handle prototype chain lookups and accessors.
* There are "slow path" labels, indicating fallback logic for more complex cases.

Based on this, I can start drafting the functionalities, JavaScript examples, and explanations.

**Constraint Checklist & Confidence Score:**

* List functionalities: Yes
* Check for Torque: Yes
* Relate to JavaScript with examples: Yes
* Code logic reasoning: Yes (with reasonable assumptions)
* Common programming errors: Yes
* Summarize function (Part 1): Yes

Confidence Score: 4/5 (Slight uncertainty in providing very specific input/output examples without knowing the exact context of how this code is called).

Strategizing complete. I will now proceed with generating the response based on the above analysis.
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/ic/keyed-store-generic.h"

#include <optional>

#include "src/codegen/code-factory.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/codegen/interface-descriptors.h"
#include "src/execution/isolate.h"
#include "src/ic/accessor-assembler.h"
#include "src/objects/contexts.h"
#include "src/objects/feedback-vector.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

enum class StoreMode {
  // kSet implements [[Set]] in the spec and traverses the prototype
  // chain to invoke setters. it's used by KeyedStoreIC and StoreIC to
  // set the properties when there is no feedback.
  kSet,
  // kDefineKeyedOwnInLiteral implements [[CreateDataProperty]] in the spec,
  // and it assumes that the receiver is a JSObject that is created by us.
  // It is used by Object.fromEntries(), CloneObjectIC and
  // StoreInArrayLiteralIC to define a property in an object without
  // traversing the prototype chain.
  // TODO(v8:12548): merge this into the more generic kDefineKeyedOwn.
  kDefineKeyedOwnInLiteral,
  // kDefineNamedOwn implements [[CreateDataProperty]] but it can deal with
  // user-defined receivers such as a JSProxy. It also assumes that the key
  // is statically known. It's used to initialize named roperties in object
  // literals and named public class fields.
  kDefineNamedOwn,
  // kDefineKeyedOwn implements [[CreateDataProperty]], but it can deal with
  // user-defined receivers such as a JSProxy, and for private class fields,
  // it will throw if the field does already exist. It's different from
  // kDefineNamedOwn in that it does not assume the key is statically known.
  // It's used to initialized computed public class fields and private
  // class fields.
  kDefineKeyedOwn
};

// With private symbols, 'define' semantics will throw if the field already
// exists, while 'update' semantics will throw if the field does not exist.
enum class PrivateNameSemantics { kUpdate, kDefine };

class KeyedStoreGenericAssembler : public AccessorAssembler {
 public:
  explicit KeyedStoreGenericAssembler(compiler::CodeAssemblerState* state,
                                      StoreMode mode)
      : AccessorAssembler(state), mode_(mode) {}

  void KeyedStoreGeneric();
  void KeyedStoreMegamorphic();

  void StoreIC_NoFeedback();

  // Generates code for [[Set]] or [[CreateDataProperty]] operation,
  // the |unique_name| is supposed to be unique otherwise this code will
  // always go to runtime.
  void StoreProperty(TNode<Context> context, TNode<JSReceiver> receiver,
                     TNode<BoolT> is_simple_receiver, TNode<Name> unique_name,
                     TNode<Object> value, LanguageMode language_mode);

  // This does [[Set]] or [[CreateDataProperty]] but it's more generic than
  // the above. It is essentially the same as "KeyedStoreGeneric" but does not
  // use feedback slot and uses a hardcoded LanguageMode instead of trying
  // to deduce it from the feedback slot's kind.
  void StoreProperty(TNode<Context> context, TNode<Object> receiver,
                     TNode<Object> key, TNode<Object> value,
                     LanguageMode language_mode);

 private:
  StoreMode mode_;

  enum UpdateLength {
    kDontChangeLength,
    kIncrementLengthByOne,
    kBumpLengthWithGap
  };

  enum UseStubCache { kUseStubCache, kDontUseStubCache };

  // Helper that is used by the public KeyedStoreGeneric, KeyedStoreMegamorphic
  // and StoreProperty.
  void KeyedStoreGeneric(TNode<Context> context, TNode<Object> receiver,
                         TNode<Object> key, TNode<Object> value,
                         Maybe<LanguageMode> language_mode,
                         UseStubCache use_stub_cache = kDontUseStubCache,
                         TNode<TaggedIndex> slot = {},
                         TNode<HeapObject> maybe_vector = {});

  void EmitGenericElementStore(TNode<JSObject> receiver,
                               TNode<Map> receiver_map,
                               TNode<Uint16T> instance_type,
                               TNode<IntPtrT> index, TNode<Object> value,
                               TNode<Context> context, Label* slow);

  // If language mode is not provided it is deduced from the feedback slot's
  // kind.
  void EmitGenericPropertyStore(TNode<JSReceiver> receiver,
                                TNode<Map> receiver_map,
                                TNode<Uint16T> instance_type,
                                const StoreICParameters* p,
                                ExitPoint* exit_point, Label* slow,
                                Maybe<LanguageMode> maybe_language_mode,
                                UseStubCache use_stub_cache);

  void EmitGenericPropertyStore(TNode<JSReceiver> receiver,
                                TNode<Map> receiver_map,
                                TNode<Uint16T> instance_type,
                                const StoreICParameters* p, Label* slow) {
    ExitPoint direct_exit(this);
    EmitGenericPropertyStore(receiver, receiver_map, instance_type, p,
                             &direct_exit, slow, Nothing<LanguageMode>(),
                             kDontUseStubCache);
  }

  void BranchIfPrototypesMayHaveReadOnlyElements(
      TNode<Map> receiver_map, Label* maybe_read_only_elements,
      Label* only_fast_writable_elements);

  void TryRewriteElements(TNode<JSObject> receiver, TNode<Map> receiver_map,
                          TNode<FixedArrayBase> elements,
                          TNode<NativeContext> native_context,
                          ElementsKind from_kind, ElementsKind to_kind,
                          Label* bailout);

  void StoreSharedArrayElement(TNode<Context> context,
                               TNode<FixedArrayBase> elements,
                               TNode<IntPtrT> index, TNode<Object> value);

  void StoreElementWithCapacity(TNode<JSObject> receiver,
                                TNode<Map> receiver_map,
                                TNode<FixedArrayBase> elements,
                                TNode<Word32T> elements_kind,
                                TNode<IntPtrT> index, TNode<Object> value,
                                TNode<Context> context, Label* slow,
                                UpdateLength update_length);

  void MaybeUpdateLengthAndReturn(TNode<JSObject> receiver,
                                  TNode<IntPtrT> index, TNode<Object> value,
                                  UpdateLength update_length);

  void TryChangeToHoleyMapHelper(TNode<JSObject> receiver,
                                 TNode<Map> receiver_map,
                                 TNode<NativeContext> native_context,
                                 ElementsKind packed_kind,
                                 ElementsKind holey_kind, Label* done,
                                 Label* map_mismatch, Label* bailout);
  void TryChangeToHoleyMap(TNode<JSObject> receiver, TNode<Map> receiver_map,
                           TNode<Word32T> current_elements_kind,
                           TNode<Context> context, ElementsKind packed_kind,
                           Label* bailout);
  void TryChangeToHoleyMapMulti(TNode<JSObject> receiver,
                                TNode<Map> receiver_map,
                                TNode<Word32T> current_elements_kind,
                                TNode<Context> context,
                                ElementsKind packed_kind,
                                ElementsKind packed_kind_2, Label* bailout);

  void LookupPropertyOnPrototypeChain(
      TNode<Map> receiver_map, TNode<Name> name, Label* accessor,
      TVariable<Object>* var_accessor_pair,
      TVariable<HeapObject>* var_accessor_holder, Label* readonly,
      Label* bailout);

  TNode<Map> FindCandidateStoreICTransitionMapHandler(TNode<Map> map,
                                                      TNode<Name> name,
                                                      Label* slow);

  bool IsSet() const { return mode_ == StoreMode::kSet; }
  bool IsDefineKeyedOwnInLiteral() const {
    return mode_ == StoreMode::kDefineKeyedOwnInLiteral;
  }
  bool IsDefineNamedOwn() const { return mode_ == StoreMode::kDefineNamedOwn; }
  bool IsDefineKeyedOwn() const { return mode_ == StoreMode::kDefineKeyedOwn; }
  bool IsAnyDefineOwn() const {
    return IsDefineNamedOwn() || IsDefineKeyedOwn();
  }

  bool ShouldCheckPrototype() const { return IsSet(); }
  bool ShouldReconfigureExisting() const { return IsDefineKeyedOwnInLiteral(); }
  bool ShouldCallSetter() const { return IsSet(); }
  bool ShouldCheckPrototypeValidity() const {
    // We don't do this for "in-literal" stores, because it is impossible for
    // the target object to be a "prototype".
    // We don't need the prototype validity check for "own" stores, because
    // we don't care about the prototype chain.
    // Thus, we need the prototype check only for ordinary stores.
    DCHECK_IMPLIES(!IsSet(), IsDefineKeyedOwnInLiteral() ||
                                 IsDefineNamedOwn() || IsDefineKeyedOwn());
    return IsSet();
  }
};

// static
void KeyedStoreMegamorphicGenerator::Generate(
    compiler::CodeAssemblerState* state) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kSet);
  assembler.KeyedStoreMegamorphic();
}

// static
void KeyedStoreGenericGenerator::Generate(compiler::CodeAssemblerState* state) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kSet);
  assembler.KeyedStoreGeneric();
}

// static
void DefineKeyedOwnGenericGenerator::Generate(
    compiler::CodeAssemblerState* state) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kDefineKeyedOwn);
  assembler.KeyedStoreGeneric();
}

// static
void StoreICNoFeedbackGenerator::Generate(compiler::CodeAssemblerState* state) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kSet);
  assembler.StoreIC_NoFeedback();
}

// static
void DefineNamedOwnICNoFeedbackGenerator::Generate(
    compiler::CodeAssemblerState* state) {
  // TODO(v8:12548): it's a hack to reuse KeyedStoreGenericAssembler for
  // DefineNamedOwnIC, we should separate it out.
  KeyedStoreGenericAssembler assembler(state, StoreMode::kDefineNamedOwn);
  assembler.StoreIC_NoFeedback();
}

// static
void KeyedStoreGenericGenerator::SetProperty(
    compiler::CodeAssemblerState* state, TNode<Context> context,
    TNode<JSReceiver> receiver, TNode<BoolT> is_simple_receiver,
    TNode<Name> name, TNode<Object> value, LanguageMode language_mode) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kSet);
  assembler.StoreProperty(context, receiver, is_simple_receiver, name, value,
                          language_mode);
}

// static
void KeyedStoreGenericGenerator::SetProperty(
    compiler::CodeAssemblerState* state, TNode<Context> context,
    TNode<Object> receiver, TNode<Object> key, TNode<Object> value,
    LanguageMode language_mode) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kSet);
  assembler.StoreProperty(context, receiver, key, value, language_mode);
}

// static
void KeyedStoreGenericGenerator::CreateDataProperty(
    compiler::CodeAssemblerState* state, TNode<Context> context,
    TNode<JSObject> receiver, TNode<Object> key, TNode<Object> value) {
  KeyedStoreGenericAssembler assembler(state,
                                       StoreMode::kDefineKeyedOwnInLiteral);
  assembler.StoreProperty(context, receiver, key, value, LanguageMode::kStrict);
}

void KeyedStoreGenericAssembler::BranchIfPrototypesMayHaveReadOnlyElements(
    TNode<Map> receiver_map, Label* maybe_read_only_elements,
    Label* only_fast_writable_elements) {
  TVARIABLE(Map, var_map);
  var_map = receiver_map;
  Label loop_body(this, &var_map);
  Goto(&loop_body);

  BIND(&loop_body);
  {
    TNode<Map> map = var_map.value();
    TNode<HeapObject> prototype = LoadMapPrototype(map);
    GotoIf(IsNull(prototype), only_fast_writable_elements);
    TNode<Map> prototype_map = LoadMap(prototype);
    var_map = prototype_map;
    TNode<Uint16T> instance_type = LoadMapInstanceType(prototype_map);
    GotoIf(IsCustomElementsReceiverInstanceType(instance_type),
           maybe_read_only_elements);
    TNode<Int32T> elements_kind = LoadMapElementsKind(prototype_map);
    GotoIf(IsFastOrNonExtensibleOrSealedElementsKind(elements_kind),
           &loop_body);
    GotoIf(Word32Equal(elements_kind, Int32Constant(NO_ELEMENTS)), &loop_body);
    Goto(maybe_read_only_elements);
  }
}

void KeyedStoreGenericAssembler::TryRewriteElements(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<FixedArrayBase> elements, TNode<NativeContext> native_context,
    ElementsKind from_kind, ElementsKind to_kind, Label* bailout) {
  DCHECK(IsFastPackedElementsKind(from_kind));
  ElementsKind holey_from_kind = GetHoleyElementsKind(from_kind);
  ElementsKind holey_to_kind = GetHoleyElementsKind(to_kind);
  if (AllocationSite::ShouldTrack(from_kind, to_kind)) {
    TrapAllocationMemento(receiver, bailout);
  }
  Label perform_transition(this), check_holey_map(this);
  TVARIABLE(Map, var_target_map);
  // Check if the receiver has the default |from_kind| map.
  {
    TNode<Map> packed_map = LoadJSArrayElementsMap(from_kind, native_context);
    GotoIf(TaggedNotEqual(receiver_map, packed_map), &check_holey_map);
    var_target_map = CAST(
        LoadContextElement(native_context, Context::ArrayMapIndex(to_kind)));
    Goto(&perform_transition);
  }

  // Check if the receiver has the default |holey_from_kind| map.
  BIND(&check_holey_map);
  {
    TNode<Object> holey_map = LoadContextElement(
        native_context, Context::ArrayMapIndex(holey_from_kind));
    GotoIf(TaggedNotEqual(receiver_map, holey_map), bailout);
    var_target_map = CAST(LoadContextElement(
        native_context, Context::ArrayMapIndex(holey_to_kind)));
    Goto(&perform_transition);
  }

  // Found a supported transition target map, perform the transition!
  BIND(&perform_transition);
  {
    if (IsDoubleElementsKind(from_kind) != IsDoubleElementsKind(to_kind)) {
      TNode<IntPtrT> capacity = LoadAndUntagFixedArrayBaseLength(elements);
      GrowElementsCapacity(receiver, elements, from_kind, to_kind, capacity,
                           capacity, bailout);
    }
    StoreMap(receiver, var_target_map.value());
  }
}

void KeyedStoreGenericAssembler::TryChangeToHoleyMapHelper(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<NativeContext> native_context, ElementsKind packed_kind,
    ElementsKind holey_kind, Label* done, Label* map_mismatch, Label* bailout) {
  TNode<Map> packed_map = LoadJSArrayElementsMap(packed_kind, native_context);
  GotoIf(TaggedNotEqual(receiver_map, packed_map), map_mismatch);
  if (AllocationSite::ShouldTrack(packed_kind, holey_kind)) {
    TrapAllocationMemento(receiver, bailout);
  }
  TNode<Map> holey_map = CAST(
      LoadContextElement(native_context, Context::ArrayMapIndex(holey_kind)));
  StoreMap(receiver, holey_map);
  Goto(done);
}

void KeyedStoreGenericAssembler::TryChangeToHoleyMap(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<Word32T> current_elements_kind, TNode<Context> context,
    ElementsKind packed_kind, Label* bailout) {
  ElementsKind holey_kind = GetHoleyElementsKind(packed_kind);
  Label already_holey(this);

  GotoIf(Word32Equal(current_elements_kind, Int32Constant(holey_kind)),
         &already_holey);
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TryChangeToHoleyMapHelper(receiver, receiver_map, native_context, packed_kind,
                            holey_kind, &already_holey, bailout, bailout);
  BIND(&already_holey);
}

void KeyedStoreGenericAssembler::TryChangeToHoleyMapMulti(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<Word32T> current_elements_kind, TNode<Context> context,
    ElementsKind packed_kind, ElementsKind packed_kind_2, Label* bailout) {
  ElementsKind holey_kind = GetHoleyElementsKind(packed_kind);
  ElementsKind holey_kind_2 = GetHoleyElementsKind(packed_kind_2);
  Label already_holey(this), check_other_kind(this);

  GotoIf(Word32Equal(current_elements_kind, Int32Constant(holey_kind)),
         &already_holey);
  GotoIf(Word32Equal(current_elements_kind, Int32Constant(holey_kind_2)),
         &already_holey);

  TNode<NativeContext> native_context = LoadNativeContext(context);
  TryChangeToHoleyMapHelper(receiver, receiver_map, native_context, packed_kind,
                            holey_kind, &already_holey, &check_other_kind,
                            bailout);
  BIND(&check_other_kind);
  TryChangeToHoleyMapHelper(receiver, receiver_map, native_context,
                            packed_kind_2, holey_kind_2, &already_holey,
                            bailout, bailout);
  BIND(&already_holey);
}

void KeyedStoreGenericAssembler::MaybeUpdateLengthAndReturn(
    TNode<JSObject> receiver, TNode<IntPtrT> index, TNode<Object> value,
    UpdateLength update_length) {
  if (update_length != kDontChangeLength) {
    TNode<Smi> new_length = SmiTag(Signed(IntPtrAdd(index, IntPtrConstant(1))));
    StoreObjectFieldNoWriteBarrier(receiver, JSArray::kLengthOffset,
                                   new_length);
  }
  Return(value);
}

void KeyedStoreGenericAssembler::StoreSharedArrayElement(
    TNode<Context> context, TNode<FixedArrayBase> elements,
    TNode<IntPtrT> index, TNode<Object> value) {
  TVARIABLE(Object, shared_value, value);
  SharedValueBarrier(context, &shared_value);
  UnsafeStoreFixedArrayElement(CAST(elements), index, shared_value.value());
  Return(value);
}

void KeyedStoreGenericAssembler::StoreElementWithCapacity(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<FixedArrayBase> elements, TNode<Word32T> elements_kind,
    TNode<IntPtrT> index, TNode<Object> value, TNode<Context> context,
    Label* slow, UpdateLength update_length) {
  if (update_length != kDontChangeLength) {
    CSA_DCHECK(this, IsJSArrayMap(receiver_map));
    // Check if the length property is writable. The fast check is only
    // supported for fast properties.
    GotoIf(IsDictionaryMap(receiver_map), slow);
    // The length property is non-configurable, so it's guaranteed to always
    // be the first property.
    TNode<DescriptorArray> descriptors = LoadMapDescriptors(receiver_map);
    TNode<Uint32T> details = LoadDetailsByDescriptorEntry(descriptors, 0);
    GotoIf(IsSetWord32(details, PropertyDetails::kAttributesReadOnlyMask),
           slow);
  }
  static_assert(OFFSET_OF_DATA_START(FixedArray) ==
                OFFSET_OF_DATA_START(FixedDoubleArray));
  const int kHeaderSize = OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag;

  Label check_double_elements(this), check_cow_elements(this);
  TNode<Map> elements_map = LoadMap(elements);
  GotoIf(IsNotFixedArrayMap(elements_map), &check_double_elements);

  // FixedArray backing store -> Smi or object elements.
  {
    TNode<IntPtrT> offset =
        ElementOffsetFromIndex(index, PACKED_ELEMENTS, kHeaderSize);
    if (!IsDefineKeyedOwnInLiteral()) {
      // Check if we're about to overwrite the hole. We can safely do that
      // only if there can be no setters on the prototype chain.
      // If we know that we're storing beyond the previous array length, we
      // can skip the hole check (and always assume the hole).
      {
        Label hole_check_passed(this);
        if (update_length == kDontChangeLength) {
          TNode<Object> element =
              CAST(Load(MachineType::AnyTagged(), elements, offset));
          GotoIf(IsNotTheHole(element), &hole_check_passed);
        }
        BranchIfPrototypesMayHaveReadOnlyElements(receiver_map, slow,
                                                  &hole_check_passed);
        BIND(&hole_check_passed);
      }
    }

    // Check if the value we're storing matches the elements_kind. Smis
    // can always be stored.
    {
      Label non_smi_value(this);
      GotoIfNot(TaggedIsSmi(value), &non_smi_value);
      // If we're about to introduce holes, ensure holey elements.
      if (update_length == kBumpLengthWithGap) {
        TryChangeToHoleyMapMulti(receiver, receiver_map, elements_kind, context,
                                 PACKED_SMI_ELEMENTS, PACKED_ELEMENTS, slow);
      }
      StoreNoWriteBarrier(MachineRepresentation::kTaggedSigned, elements,
                          offset, value);
      MaybeUpdateLengthAndReturn(receiver, index, value, update_length);

      BIND(&non_smi_value);
    }

    // Check if we already have object elements; just do the store if so.
    {
      Label must_transition(this);
      static_assert(PACKED_SMI_ELEMENTS == 0);
      static_assert(HOLEY_SMI_ELEMENTS == 1);
      GotoIf(Int32LessThanOrEqual(elements_kind,
                                  Int32Constant(HOLEY_SMI_ELEMENTS)),
             &must_transition);
      if (update_length == kBumpLengthWithGap) {
        TryChangeToHoleyMap(receiver, receiver_map, elements_kind, context,
                            PACKED_ELEMENTS, slow);
      }
      Store(elements, offset, value);
      MaybeUpdateLengthAndReturn(receiver, index, value, update_length);

      BIND(&must_transition);
    }

    // Transition to the required ElementsKind.
    {
      Label transition_to_double(this), transition_to_object(this);
      TNode<NativeContext> native_context = LoadNativeContext(context);
      Branch(IsHeapNumber(CAST(value)), &transition_to_double,
             &transition_to_object);
      BIND(&transition_to_double);
      {
        // If we're adding holes at the end, always transition to a holey
        // elements kind, otherwise try to remain packed.
        ElementsKind target_kind = update_length == kBumpLengthWithGap
                                       ? HOLEY_DOUBLE_ELEMENTS
                                       : PACKED_DOUBLE_ELEMENTS;
        TryRewriteElements(receiver, receiver_map, elements, native_context,
                           PACKED_SMI_ELEMENTS, target_kind, slow);
        // Reload migrated elements.
        TNode<FixedArrayBase> double_elements = LoadElements(receiver);
        TNode<IntPtrT> double_offset =
            ElementOffsetFromIndex(index, PACKED_DOUBLE_ELEMENTS, kHeaderSize);
        // Make sure we do not store signalling NaNs into double arrays.
        TNode<Float64T> double_value =
            Float64SilenceNaN(LoadHeapNumberValue(CAST(value)));
        StoreNoWriteBarrier(MachineRepresentation::kFloat64, double_elements,
                            double_offset, double_value);
        MaybeUpdateLengthAndReturn(receiver, index, value, update_length);
      }

      BIND(&transition_to_object);
      {
        // If we're adding holes at the end, always transition to a holey
        // elements kind, otherwise try to remain packed.
        ElementsKind target_kind = update_length == kBumpLengthWithGap
                                       ? HOLEY_ELEMENTS
                                       : PACKED_ELEMENTS;
        TryRewriteElements(receiver, receiver_map, elements, native_context,
                           PACKED_SMI_ELEMENTS, target_kind, slow);
        // The elements backing store didn't change, no reload necessary.
        CSA_DCHECK(this, TaggedEqual(elements, LoadElements(receiver)));
        Store(elements, offset, value);
        MaybeUpdateLengthAndReturn(receiver, index, value, update_length);
      }
    }
  }

  BIND(&check_double_elements);
  GotoIf(IsNotFixedDoubleArrayMap(elements_map), &check_cow_elements);
  // FixedDoubleArray backing store -> double elements.
  {
    TNode<IntPtrT> offset =
        ElementOffsetFromIndex(index, PACKED_DOUBLE_ELEMENTS, kHeaderSize);
    if (!IsDefineKeyedOwnInLiteral()) {
      // Check if we're about to overwrite the hole. We can safely do that
      // only if there can be no setters on the prototype chain.
      {
        Label hole_check_passed(this);
        // If we know that we're storing beyond the previous array length, we
        // can skip the hole check (and always assume the hole).
        if (update_length == kDontChangeLength) {
          Label found_hole(this);
          LoadDoubleWithHoleCheck(elements, offset, &found_hole,
                                  MachineType::None());
          Goto(&hole_check_passed);
          BIND(&found_hole);
        }
        BranchIfPrototypesMayHaveReadOnlyElements(receiver_map, slow,
                                                  &hole_check_passed);
        BIND(&hole_check_passed);
      }
    }

    // Try to store the value as a double.
    {
      Label non_number_value(this);
      TNode<Float64T> double_value =
          TryTaggedToFloat64(value, &non_number_value);

      // Make sure we do not store signalling NaNs into double arrays.
      double_value = Float64SilenceNaN(double_value);
      // If we're about to introduce holes, ensure holey elements.
      if (update_length == kBumpLengthWithGap) {
        TryChangeToHoleyMap(receiver, receiver_map, elements_kind, context,
                            PACKED_DOUBLE_ELEMENTS, slow);
      }
      StoreNoWriteBarrier(MachineRepresentation::kFloat64, elements, offset,
                          double_value);
      MaybeUpdateLengthAndReturn(receiver, index, value, update_length);

      BIND(&non_number_value);
    }

    // Transition to object elements.
    {
      TNode<NativeContext> native_context = LoadNativeContext(context);
      ElementsKind target_kind = update_length == kBumpLengthWithGap
                                     ? HOLEY_ELEMENTS
                                     : PACKED_ELEMENTS;
      TryRewriteElements(receiver, receiver_map, elements, native_context,
                         PACKED_DOUBLE_ELEMENTS, target_kind, slow);
      // Reload migrated elements.
      TNode<FixedArrayBase> fast_elements = LoadElements(receiver);
      TNode<IntPtrT> fast_offset =
          ElementOffsetFromIndex(index, PACKED_ELEMENTS, kHeaderSize);
      Store(fast_elements, fast_offset, value);
      MaybeUpdateLengthAndReturn(receiver, index, value, update_length);
    }
  }

  BIND(&check_cow_elements);
  {
    // TODO(jkummerow): Use GrowElementsCapacity instead of bailing out.
    Goto(slow);
  }
}

void KeyedStoreGenericAssembler::EmitGenericElementStore(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<Uint16T> instance_type, TNode<IntPtrT> index, TNode<Object> value,
    TNode<Context> context, Label* slow) {
  Label if_fast(this), if_in_bounds(this), if_increment_length_by_one(this),
      if_bump_length_with_gap(this), if_grow(this), if_nonfast(this),
      if_typed_array(this), if_dictionary(this), if_shared_array(this);
  TNode<FixedArrayBase> elements = LoadElements(receiver);
  TNode<Int32T> elements_kind = LoadMapElementsKind(receiver_map);
  Branch(IsFastElementsKind(elements_kind), &if_fast, &if_nonfast);
  BIND(&if_fast);
  Label if_array(this);
  GotoIf(IsJSArrayInstanceType(instance_type), &if_array);
  {
    TNode<IntPtrT> capacity = LoadAndUntagFixedArrayBaseLength(elements);
    Branch(UintPtrLessThan(index, capacity), &if_in_bounds, &if_grow);
  }
  BIND(&if_array);
  {
    TNode<IntPtrT> length =
        PositiveSmiUntag(LoadFastJSArrayLength(CAST(receiver)));
    GotoIf(UintPtrLessThan(index, length), &if_in_bounds);
    TNode<IntPtrT> capacity = LoadAndUntagFixedArrayBaseLength(elements);
    GotoIf
Prompt: 
```
这是目录为v8/src/ic/keyed-store-generic.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/keyed-store-generic.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/ic/keyed-store-generic.h"

#include <optional>

#include "src/codegen/code-factory.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/codegen/interface-descriptors.h"
#include "src/execution/isolate.h"
#include "src/ic/accessor-assembler.h"
#include "src/objects/contexts.h"
#include "src/objects/feedback-vector.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

enum class StoreMode {
  // kSet implements [[Set]] in the spec and traverses the prototype
  // chain to invoke setters. it's used by KeyedStoreIC and StoreIC to
  // set the properties when there is no feedback.
  kSet,
  // kDefineKeyedOwnInLiteral implements [[CreateDataProperty]] in the spec,
  // and it assumes that the receiver is a JSObject that is created by us.
  // It is used by Object.fromEntries(), CloneObjectIC and
  // StoreInArrayLiteralIC to define a property in an object without
  // traversing the prototype chain.
  // TODO(v8:12548): merge this into the more generic kDefineKeyedOwn.
  kDefineKeyedOwnInLiteral,
  // kDefineNamedOwn implements [[CreateDataProperty]] but it can deal with
  // user-defined receivers such as a JSProxy. It also assumes that the key
  // is statically known. It's used to initialize named roperties in object
  // literals and named public class fields.
  kDefineNamedOwn,
  // kDefineKeyedOwn implements [[CreateDataProperty]], but it can deal with
  // user-defined receivers such as a JSProxy, and for private class fields,
  // it will throw if the field does already exist. It's different from
  // kDefineNamedOwn in that it does not assume the key is statically known.
  // It's used to initialized computed public class fields and private
  // class fields.
  kDefineKeyedOwn
};

// With private symbols, 'define' semantics will throw if the field already
// exists, while 'update' semantics will throw if the field does not exist.
enum class PrivateNameSemantics { kUpdate, kDefine };

class KeyedStoreGenericAssembler : public AccessorAssembler {
 public:
  explicit KeyedStoreGenericAssembler(compiler::CodeAssemblerState* state,
                                      StoreMode mode)
      : AccessorAssembler(state), mode_(mode) {}

  void KeyedStoreGeneric();
  void KeyedStoreMegamorphic();

  void StoreIC_NoFeedback();

  // Generates code for [[Set]] or [[CreateDataProperty]] operation,
  // the |unique_name| is supposed to be unique otherwise this code will
  // always go to runtime.
  void StoreProperty(TNode<Context> context, TNode<JSReceiver> receiver,
                     TNode<BoolT> is_simple_receiver, TNode<Name> unique_name,
                     TNode<Object> value, LanguageMode language_mode);

  // This does [[Set]] or [[CreateDataProperty]] but it's more generic than
  // the above. It is essentially the same as "KeyedStoreGeneric" but does not
  // use feedback slot and uses a hardcoded LanguageMode instead of trying
  // to deduce it from the feedback slot's kind.
  void StoreProperty(TNode<Context> context, TNode<Object> receiver,
                     TNode<Object> key, TNode<Object> value,
                     LanguageMode language_mode);

 private:
  StoreMode mode_;

  enum UpdateLength {
    kDontChangeLength,
    kIncrementLengthByOne,
    kBumpLengthWithGap
  };

  enum UseStubCache { kUseStubCache, kDontUseStubCache };

  // Helper that is used by the public KeyedStoreGeneric, KeyedStoreMegamorphic
  // and StoreProperty.
  void KeyedStoreGeneric(TNode<Context> context, TNode<Object> receiver,
                         TNode<Object> key, TNode<Object> value,
                         Maybe<LanguageMode> language_mode,
                         UseStubCache use_stub_cache = kDontUseStubCache,
                         TNode<TaggedIndex> slot = {},
                         TNode<HeapObject> maybe_vector = {});

  void EmitGenericElementStore(TNode<JSObject> receiver,
                               TNode<Map> receiver_map,
                               TNode<Uint16T> instance_type,
                               TNode<IntPtrT> index, TNode<Object> value,
                               TNode<Context> context, Label* slow);

  // If language mode is not provided it is deduced from the feedback slot's
  // kind.
  void EmitGenericPropertyStore(TNode<JSReceiver> receiver,
                                TNode<Map> receiver_map,
                                TNode<Uint16T> instance_type,
                                const StoreICParameters* p,
                                ExitPoint* exit_point, Label* slow,
                                Maybe<LanguageMode> maybe_language_mode,
                                UseStubCache use_stub_cache);

  void EmitGenericPropertyStore(TNode<JSReceiver> receiver,
                                TNode<Map> receiver_map,
                                TNode<Uint16T> instance_type,
                                const StoreICParameters* p, Label* slow) {
    ExitPoint direct_exit(this);
    EmitGenericPropertyStore(receiver, receiver_map, instance_type, p,
                             &direct_exit, slow, Nothing<LanguageMode>(),
                             kDontUseStubCache);
  }

  void BranchIfPrototypesMayHaveReadOnlyElements(
      TNode<Map> receiver_map, Label* maybe_read_only_elements,
      Label* only_fast_writable_elements);

  void TryRewriteElements(TNode<JSObject> receiver, TNode<Map> receiver_map,
                          TNode<FixedArrayBase> elements,
                          TNode<NativeContext> native_context,
                          ElementsKind from_kind, ElementsKind to_kind,
                          Label* bailout);

  void StoreSharedArrayElement(TNode<Context> context,
                               TNode<FixedArrayBase> elements,
                               TNode<IntPtrT> index, TNode<Object> value);

  void StoreElementWithCapacity(TNode<JSObject> receiver,
                                TNode<Map> receiver_map,
                                TNode<FixedArrayBase> elements,
                                TNode<Word32T> elements_kind,
                                TNode<IntPtrT> index, TNode<Object> value,
                                TNode<Context> context, Label* slow,
                                UpdateLength update_length);

  void MaybeUpdateLengthAndReturn(TNode<JSObject> receiver,
                                  TNode<IntPtrT> index, TNode<Object> value,
                                  UpdateLength update_length);

  void TryChangeToHoleyMapHelper(TNode<JSObject> receiver,
                                 TNode<Map> receiver_map,
                                 TNode<NativeContext> native_context,
                                 ElementsKind packed_kind,
                                 ElementsKind holey_kind, Label* done,
                                 Label* map_mismatch, Label* bailout);
  void TryChangeToHoleyMap(TNode<JSObject> receiver, TNode<Map> receiver_map,
                           TNode<Word32T> current_elements_kind,
                           TNode<Context> context, ElementsKind packed_kind,
                           Label* bailout);
  void TryChangeToHoleyMapMulti(TNode<JSObject> receiver,
                                TNode<Map> receiver_map,
                                TNode<Word32T> current_elements_kind,
                                TNode<Context> context,
                                ElementsKind packed_kind,
                                ElementsKind packed_kind_2, Label* bailout);

  void LookupPropertyOnPrototypeChain(
      TNode<Map> receiver_map, TNode<Name> name, Label* accessor,
      TVariable<Object>* var_accessor_pair,
      TVariable<HeapObject>* var_accessor_holder, Label* readonly,
      Label* bailout);

  TNode<Map> FindCandidateStoreICTransitionMapHandler(TNode<Map> map,
                                                      TNode<Name> name,
                                                      Label* slow);

  bool IsSet() const { return mode_ == StoreMode::kSet; }
  bool IsDefineKeyedOwnInLiteral() const {
    return mode_ == StoreMode::kDefineKeyedOwnInLiteral;
  }
  bool IsDefineNamedOwn() const { return mode_ == StoreMode::kDefineNamedOwn; }
  bool IsDefineKeyedOwn() const { return mode_ == StoreMode::kDefineKeyedOwn; }
  bool IsAnyDefineOwn() const {
    return IsDefineNamedOwn() || IsDefineKeyedOwn();
  }

  bool ShouldCheckPrototype() const { return IsSet(); }
  bool ShouldReconfigureExisting() const { return IsDefineKeyedOwnInLiteral(); }
  bool ShouldCallSetter() const { return IsSet(); }
  bool ShouldCheckPrototypeValidity() const {
    // We don't do this for "in-literal" stores, because it is impossible for
    // the target object to be a "prototype".
    // We don't need the prototype validity check for "own" stores, because
    // we don't care about the prototype chain.
    // Thus, we need the prototype check only for ordinary stores.
    DCHECK_IMPLIES(!IsSet(), IsDefineKeyedOwnInLiteral() ||
                                 IsDefineNamedOwn() || IsDefineKeyedOwn());
    return IsSet();
  }
};

// static
void KeyedStoreMegamorphicGenerator::Generate(
    compiler::CodeAssemblerState* state) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kSet);
  assembler.KeyedStoreMegamorphic();
}

// static
void KeyedStoreGenericGenerator::Generate(compiler::CodeAssemblerState* state) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kSet);
  assembler.KeyedStoreGeneric();
}

// static
void DefineKeyedOwnGenericGenerator::Generate(
    compiler::CodeAssemblerState* state) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kDefineKeyedOwn);
  assembler.KeyedStoreGeneric();
}

// static
void StoreICNoFeedbackGenerator::Generate(compiler::CodeAssemblerState* state) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kSet);
  assembler.StoreIC_NoFeedback();
}

// static
void DefineNamedOwnICNoFeedbackGenerator::Generate(
    compiler::CodeAssemblerState* state) {
  // TODO(v8:12548): it's a hack to reuse KeyedStoreGenericAssembler for
  // DefineNamedOwnIC, we should separate it out.
  KeyedStoreGenericAssembler assembler(state, StoreMode::kDefineNamedOwn);
  assembler.StoreIC_NoFeedback();
}

// static
void KeyedStoreGenericGenerator::SetProperty(
    compiler::CodeAssemblerState* state, TNode<Context> context,
    TNode<JSReceiver> receiver, TNode<BoolT> is_simple_receiver,
    TNode<Name> name, TNode<Object> value, LanguageMode language_mode) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kSet);
  assembler.StoreProperty(context, receiver, is_simple_receiver, name, value,
                          language_mode);
}

// static
void KeyedStoreGenericGenerator::SetProperty(
    compiler::CodeAssemblerState* state, TNode<Context> context,
    TNode<Object> receiver, TNode<Object> key, TNode<Object> value,
    LanguageMode language_mode) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kSet);
  assembler.StoreProperty(context, receiver, key, value, language_mode);
}

// static
void KeyedStoreGenericGenerator::CreateDataProperty(
    compiler::CodeAssemblerState* state, TNode<Context> context,
    TNode<JSObject> receiver, TNode<Object> key, TNode<Object> value) {
  KeyedStoreGenericAssembler assembler(state,
                                       StoreMode::kDefineKeyedOwnInLiteral);
  assembler.StoreProperty(context, receiver, key, value, LanguageMode::kStrict);
}

void KeyedStoreGenericAssembler::BranchIfPrototypesMayHaveReadOnlyElements(
    TNode<Map> receiver_map, Label* maybe_read_only_elements,
    Label* only_fast_writable_elements) {
  TVARIABLE(Map, var_map);
  var_map = receiver_map;
  Label loop_body(this, &var_map);
  Goto(&loop_body);

  BIND(&loop_body);
  {
    TNode<Map> map = var_map.value();
    TNode<HeapObject> prototype = LoadMapPrototype(map);
    GotoIf(IsNull(prototype), only_fast_writable_elements);
    TNode<Map> prototype_map = LoadMap(prototype);
    var_map = prototype_map;
    TNode<Uint16T> instance_type = LoadMapInstanceType(prototype_map);
    GotoIf(IsCustomElementsReceiverInstanceType(instance_type),
           maybe_read_only_elements);
    TNode<Int32T> elements_kind = LoadMapElementsKind(prototype_map);
    GotoIf(IsFastOrNonExtensibleOrSealedElementsKind(elements_kind),
           &loop_body);
    GotoIf(Word32Equal(elements_kind, Int32Constant(NO_ELEMENTS)), &loop_body);
    Goto(maybe_read_only_elements);
  }
}

void KeyedStoreGenericAssembler::TryRewriteElements(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<FixedArrayBase> elements, TNode<NativeContext> native_context,
    ElementsKind from_kind, ElementsKind to_kind, Label* bailout) {
  DCHECK(IsFastPackedElementsKind(from_kind));
  ElementsKind holey_from_kind = GetHoleyElementsKind(from_kind);
  ElementsKind holey_to_kind = GetHoleyElementsKind(to_kind);
  if (AllocationSite::ShouldTrack(from_kind, to_kind)) {
    TrapAllocationMemento(receiver, bailout);
  }
  Label perform_transition(this), check_holey_map(this);
  TVARIABLE(Map, var_target_map);
  // Check if the receiver has the default |from_kind| map.
  {
    TNode<Map> packed_map = LoadJSArrayElementsMap(from_kind, native_context);
    GotoIf(TaggedNotEqual(receiver_map, packed_map), &check_holey_map);
    var_target_map = CAST(
        LoadContextElement(native_context, Context::ArrayMapIndex(to_kind)));
    Goto(&perform_transition);
  }

  // Check if the receiver has the default |holey_from_kind| map.
  BIND(&check_holey_map);
  {
    TNode<Object> holey_map = LoadContextElement(
        native_context, Context::ArrayMapIndex(holey_from_kind));
    GotoIf(TaggedNotEqual(receiver_map, holey_map), bailout);
    var_target_map = CAST(LoadContextElement(
        native_context, Context::ArrayMapIndex(holey_to_kind)));
    Goto(&perform_transition);
  }

  // Found a supported transition target map, perform the transition!
  BIND(&perform_transition);
  {
    if (IsDoubleElementsKind(from_kind) != IsDoubleElementsKind(to_kind)) {
      TNode<IntPtrT> capacity = LoadAndUntagFixedArrayBaseLength(elements);
      GrowElementsCapacity(receiver, elements, from_kind, to_kind, capacity,
                           capacity, bailout);
    }
    StoreMap(receiver, var_target_map.value());
  }
}

void KeyedStoreGenericAssembler::TryChangeToHoleyMapHelper(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<NativeContext> native_context, ElementsKind packed_kind,
    ElementsKind holey_kind, Label* done, Label* map_mismatch, Label* bailout) {
  TNode<Map> packed_map = LoadJSArrayElementsMap(packed_kind, native_context);
  GotoIf(TaggedNotEqual(receiver_map, packed_map), map_mismatch);
  if (AllocationSite::ShouldTrack(packed_kind, holey_kind)) {
    TrapAllocationMemento(receiver, bailout);
  }
  TNode<Map> holey_map = CAST(
      LoadContextElement(native_context, Context::ArrayMapIndex(holey_kind)));
  StoreMap(receiver, holey_map);
  Goto(done);
}

void KeyedStoreGenericAssembler::TryChangeToHoleyMap(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<Word32T> current_elements_kind, TNode<Context> context,
    ElementsKind packed_kind, Label* bailout) {
  ElementsKind holey_kind = GetHoleyElementsKind(packed_kind);
  Label already_holey(this);

  GotoIf(Word32Equal(current_elements_kind, Int32Constant(holey_kind)),
         &already_holey);
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TryChangeToHoleyMapHelper(receiver, receiver_map, native_context, packed_kind,
                            holey_kind, &already_holey, bailout, bailout);
  BIND(&already_holey);
}

void KeyedStoreGenericAssembler::TryChangeToHoleyMapMulti(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<Word32T> current_elements_kind, TNode<Context> context,
    ElementsKind packed_kind, ElementsKind packed_kind_2, Label* bailout) {
  ElementsKind holey_kind = GetHoleyElementsKind(packed_kind);
  ElementsKind holey_kind_2 = GetHoleyElementsKind(packed_kind_2);
  Label already_holey(this), check_other_kind(this);

  GotoIf(Word32Equal(current_elements_kind, Int32Constant(holey_kind)),
         &already_holey);
  GotoIf(Word32Equal(current_elements_kind, Int32Constant(holey_kind_2)),
         &already_holey);

  TNode<NativeContext> native_context = LoadNativeContext(context);
  TryChangeToHoleyMapHelper(receiver, receiver_map, native_context, packed_kind,
                            holey_kind, &already_holey, &check_other_kind,
                            bailout);
  BIND(&check_other_kind);
  TryChangeToHoleyMapHelper(receiver, receiver_map, native_context,
                            packed_kind_2, holey_kind_2, &already_holey,
                            bailout, bailout);
  BIND(&already_holey);
}

void KeyedStoreGenericAssembler::MaybeUpdateLengthAndReturn(
    TNode<JSObject> receiver, TNode<IntPtrT> index, TNode<Object> value,
    UpdateLength update_length) {
  if (update_length != kDontChangeLength) {
    TNode<Smi> new_length = SmiTag(Signed(IntPtrAdd(index, IntPtrConstant(1))));
    StoreObjectFieldNoWriteBarrier(receiver, JSArray::kLengthOffset,
                                   new_length);
  }
  Return(value);
}

void KeyedStoreGenericAssembler::StoreSharedArrayElement(
    TNode<Context> context, TNode<FixedArrayBase> elements,
    TNode<IntPtrT> index, TNode<Object> value) {
  TVARIABLE(Object, shared_value, value);
  SharedValueBarrier(context, &shared_value);
  UnsafeStoreFixedArrayElement(CAST(elements), index, shared_value.value());
  Return(value);
}

void KeyedStoreGenericAssembler::StoreElementWithCapacity(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<FixedArrayBase> elements, TNode<Word32T> elements_kind,
    TNode<IntPtrT> index, TNode<Object> value, TNode<Context> context,
    Label* slow, UpdateLength update_length) {
  if (update_length != kDontChangeLength) {
    CSA_DCHECK(this, IsJSArrayMap(receiver_map));
    // Check if the length property is writable. The fast check is only
    // supported for fast properties.
    GotoIf(IsDictionaryMap(receiver_map), slow);
    // The length property is non-configurable, so it's guaranteed to always
    // be the first property.
    TNode<DescriptorArray> descriptors = LoadMapDescriptors(receiver_map);
    TNode<Uint32T> details = LoadDetailsByDescriptorEntry(descriptors, 0);
    GotoIf(IsSetWord32(details, PropertyDetails::kAttributesReadOnlyMask),
           slow);
  }
  static_assert(OFFSET_OF_DATA_START(FixedArray) ==
                OFFSET_OF_DATA_START(FixedDoubleArray));
  const int kHeaderSize = OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag;

  Label check_double_elements(this), check_cow_elements(this);
  TNode<Map> elements_map = LoadMap(elements);
  GotoIf(IsNotFixedArrayMap(elements_map), &check_double_elements);

  // FixedArray backing store -> Smi or object elements.
  {
    TNode<IntPtrT> offset =
        ElementOffsetFromIndex(index, PACKED_ELEMENTS, kHeaderSize);
    if (!IsDefineKeyedOwnInLiteral()) {
      // Check if we're about to overwrite the hole. We can safely do that
      // only if there can be no setters on the prototype chain.
      // If we know that we're storing beyond the previous array length, we
      // can skip the hole check (and always assume the hole).
      {
        Label hole_check_passed(this);
        if (update_length == kDontChangeLength) {
          TNode<Object> element =
              CAST(Load(MachineType::AnyTagged(), elements, offset));
          GotoIf(IsNotTheHole(element), &hole_check_passed);
        }
        BranchIfPrototypesMayHaveReadOnlyElements(receiver_map, slow,
                                                  &hole_check_passed);
        BIND(&hole_check_passed);
      }
    }

    // Check if the value we're storing matches the elements_kind. Smis
    // can always be stored.
    {
      Label non_smi_value(this);
      GotoIfNot(TaggedIsSmi(value), &non_smi_value);
      // If we're about to introduce holes, ensure holey elements.
      if (update_length == kBumpLengthWithGap) {
        TryChangeToHoleyMapMulti(receiver, receiver_map, elements_kind, context,
                                 PACKED_SMI_ELEMENTS, PACKED_ELEMENTS, slow);
      }
      StoreNoWriteBarrier(MachineRepresentation::kTaggedSigned, elements,
                          offset, value);
      MaybeUpdateLengthAndReturn(receiver, index, value, update_length);

      BIND(&non_smi_value);
    }

    // Check if we already have object elements; just do the store if so.
    {
      Label must_transition(this);
      static_assert(PACKED_SMI_ELEMENTS == 0);
      static_assert(HOLEY_SMI_ELEMENTS == 1);
      GotoIf(Int32LessThanOrEqual(elements_kind,
                                  Int32Constant(HOLEY_SMI_ELEMENTS)),
             &must_transition);
      if (update_length == kBumpLengthWithGap) {
        TryChangeToHoleyMap(receiver, receiver_map, elements_kind, context,
                            PACKED_ELEMENTS, slow);
      }
      Store(elements, offset, value);
      MaybeUpdateLengthAndReturn(receiver, index, value, update_length);

      BIND(&must_transition);
    }

    // Transition to the required ElementsKind.
    {
      Label transition_to_double(this), transition_to_object(this);
      TNode<NativeContext> native_context = LoadNativeContext(context);
      Branch(IsHeapNumber(CAST(value)), &transition_to_double,
             &transition_to_object);
      BIND(&transition_to_double);
      {
        // If we're adding holes at the end, always transition to a holey
        // elements kind, otherwise try to remain packed.
        ElementsKind target_kind = update_length == kBumpLengthWithGap
                                       ? HOLEY_DOUBLE_ELEMENTS
                                       : PACKED_DOUBLE_ELEMENTS;
        TryRewriteElements(receiver, receiver_map, elements, native_context,
                           PACKED_SMI_ELEMENTS, target_kind, slow);
        // Reload migrated elements.
        TNode<FixedArrayBase> double_elements = LoadElements(receiver);
        TNode<IntPtrT> double_offset =
            ElementOffsetFromIndex(index, PACKED_DOUBLE_ELEMENTS, kHeaderSize);
        // Make sure we do not store signalling NaNs into double arrays.
        TNode<Float64T> double_value =
            Float64SilenceNaN(LoadHeapNumberValue(CAST(value)));
        StoreNoWriteBarrier(MachineRepresentation::kFloat64, double_elements,
                            double_offset, double_value);
        MaybeUpdateLengthAndReturn(receiver, index, value, update_length);
      }

      BIND(&transition_to_object);
      {
        // If we're adding holes at the end, always transition to a holey
        // elements kind, otherwise try to remain packed.
        ElementsKind target_kind = update_length == kBumpLengthWithGap
                                       ? HOLEY_ELEMENTS
                                       : PACKED_ELEMENTS;
        TryRewriteElements(receiver, receiver_map, elements, native_context,
                           PACKED_SMI_ELEMENTS, target_kind, slow);
        // The elements backing store didn't change, no reload necessary.
        CSA_DCHECK(this, TaggedEqual(elements, LoadElements(receiver)));
        Store(elements, offset, value);
        MaybeUpdateLengthAndReturn(receiver, index, value, update_length);
      }
    }
  }

  BIND(&check_double_elements);
  GotoIf(IsNotFixedDoubleArrayMap(elements_map), &check_cow_elements);
  // FixedDoubleArray backing store -> double elements.
  {
    TNode<IntPtrT> offset =
        ElementOffsetFromIndex(index, PACKED_DOUBLE_ELEMENTS, kHeaderSize);
    if (!IsDefineKeyedOwnInLiteral()) {
      // Check if we're about to overwrite the hole. We can safely do that
      // only if there can be no setters on the prototype chain.
      {
        Label hole_check_passed(this);
        // If we know that we're storing beyond the previous array length, we
        // can skip the hole check (and always assume the hole).
        if (update_length == kDontChangeLength) {
          Label found_hole(this);
          LoadDoubleWithHoleCheck(elements, offset, &found_hole,
                                  MachineType::None());
          Goto(&hole_check_passed);
          BIND(&found_hole);
        }
        BranchIfPrototypesMayHaveReadOnlyElements(receiver_map, slow,
                                                  &hole_check_passed);
        BIND(&hole_check_passed);
      }
    }

    // Try to store the value as a double.
    {
      Label non_number_value(this);
      TNode<Float64T> double_value =
          TryTaggedToFloat64(value, &non_number_value);

      // Make sure we do not store signalling NaNs into double arrays.
      double_value = Float64SilenceNaN(double_value);
      // If we're about to introduce holes, ensure holey elements.
      if (update_length == kBumpLengthWithGap) {
        TryChangeToHoleyMap(receiver, receiver_map, elements_kind, context,
                            PACKED_DOUBLE_ELEMENTS, slow);
      }
      StoreNoWriteBarrier(MachineRepresentation::kFloat64, elements, offset,
                          double_value);
      MaybeUpdateLengthAndReturn(receiver, index, value, update_length);

      BIND(&non_number_value);
    }

    // Transition to object elements.
    {
      TNode<NativeContext> native_context = LoadNativeContext(context);
      ElementsKind target_kind = update_length == kBumpLengthWithGap
                                     ? HOLEY_ELEMENTS
                                     : PACKED_ELEMENTS;
      TryRewriteElements(receiver, receiver_map, elements, native_context,
                         PACKED_DOUBLE_ELEMENTS, target_kind, slow);
      // Reload migrated elements.
      TNode<FixedArrayBase> fast_elements = LoadElements(receiver);
      TNode<IntPtrT> fast_offset =
          ElementOffsetFromIndex(index, PACKED_ELEMENTS, kHeaderSize);
      Store(fast_elements, fast_offset, value);
      MaybeUpdateLengthAndReturn(receiver, index, value, update_length);
    }
  }

  BIND(&check_cow_elements);
  {
    // TODO(jkummerow): Use GrowElementsCapacity instead of bailing out.
    Goto(slow);
  }
}

void KeyedStoreGenericAssembler::EmitGenericElementStore(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<Uint16T> instance_type, TNode<IntPtrT> index, TNode<Object> value,
    TNode<Context> context, Label* slow) {
  Label if_fast(this), if_in_bounds(this), if_increment_length_by_one(this),
      if_bump_length_with_gap(this), if_grow(this), if_nonfast(this),
      if_typed_array(this), if_dictionary(this), if_shared_array(this);
  TNode<FixedArrayBase> elements = LoadElements(receiver);
  TNode<Int32T> elements_kind = LoadMapElementsKind(receiver_map);
  Branch(IsFastElementsKind(elements_kind), &if_fast, &if_nonfast);
  BIND(&if_fast);
  Label if_array(this);
  GotoIf(IsJSArrayInstanceType(instance_type), &if_array);
  {
    TNode<IntPtrT> capacity = LoadAndUntagFixedArrayBaseLength(elements);
    Branch(UintPtrLessThan(index, capacity), &if_in_bounds, &if_grow);
  }
  BIND(&if_array);
  {
    TNode<IntPtrT> length =
        PositiveSmiUntag(LoadFastJSArrayLength(CAST(receiver)));
    GotoIf(UintPtrLessThan(index, length), &if_in_bounds);
    TNode<IntPtrT> capacity = LoadAndUntagFixedArrayBaseLength(elements);
    GotoIf(UintPtrGreaterThanOrEqual(index, capacity), &if_grow);
    Branch(WordEqual(index, length), &if_increment_length_by_one,
           &if_bump_length_with_gap);
  }

  BIND(&if_in_bounds);
  {
    StoreElementWithCapacity(receiver, receiver_map, elements, elements_kind,
                             index, value, context, slow, kDontChangeLength);
  }

  BIND(&if_increment_length_by_one);
  {
    StoreElementWithCapacity(receiver, receiver_map, elements, elements_kind,
                             index, value, context, slow,
                             kIncrementLengthByOne);
  }

  BIND(&if_bump_length_with_gap);
  {
    StoreElementWithCapacity(receiver, receiver_map, elements, elements_kind,
                             index, value, context, slow, kBumpLengthWithGap);
  }

  // Out-of-capacity accesses (index >= capacity) jump here. Additionally,
  // an ElementsKind transition might be necessary.
  // The index can also be negative or larger than kMaxElementIndex at this
  // point! Jump to the runtime in that case to convert it to a named property.
  BIND(&if_grow);
  {
    Comment("Grow backing store");
    // TODO(jkummerow): Support inline backing store growth.
    Goto(slow);
  }

  // Any ElementsKind > LAST_FAST_ELEMENTS_KIND jumps here for further
  // dispatch.
  BIND(&if_nonfast);
  {
    static_assert(LAST_ELEMENTS_KIND ==
                  LAST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND);
    GotoIf(Int32GreaterThanOrEqual(
               elements_kind,
               Int32Constant(FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND)),
           &if_typed_array);
    GotoIf(Word32Equal(elements_kind, Int32Constant(DICTIONARY_ELEMENTS)),
           &if_dictionary);
    GotoIf(Word32Equal(elements_kind, Int32Constant(SHARED_ARRAY_ELEMENTS)),
           &if_shared_array);
    Goto(slow);
  }

  BIND(&if_dictionary);
  {
    Comment("Dictionary");
    // TODO(jkummerow): Support storing to dictionary elements.
    Goto(slow);
  }

  BIND(&if_typed_array);
  {
    Comment("Typed array");
    // TODO(jkummerow): Support typed arrays. Note: RAB / GSAB backed typed
    // arrays end up here too.
    Goto(slow);
  }

  BIND(&if_shared_array);
  {
    TNode<IntPtrT> length = LoadAndUntagFixedArrayBaseLength(elements);
    GotoIf(UintPtrGreaterThanOrEqual(index, length), slow);
    StoreSharedArrayElement(context, elements, index, value);
  }
}

void KeyedStoreGenericAssembler::LookupPropertyOnPrototypeChain(
    TNode<Map> receiver_map, TNode<Name> name, Label* accessor,
    TVariable<Object>* var_accessor_pair,
    TVariable<HeapObject>* var_accessor_holder, Label* readonly,
    Label* bailout) {
  Label ok_to_write(this);
  TVARIABLE(HeapObject, var_holder);
  TVARIABLE(Map, var_holder_map);
  var_holder = LoadMapPrototype(receiver_map);
  var_holder_map = LoadMap(var_holder.value());

  Label loop(this, {&var_holder, &var_holder_map});
  Goto(&loop);
  BIND(&loop);
  {
    TNode<HeapObject> holder = var_holder.value();
    GotoIf(IsNull(holder), &ok_to_write);
    TNode<Map> holder_map = var_holder_map.value();
    TNode<Uint16T> instance_type = LoadMapInstanceType(holder_map);
    Label next_proto(this);
    {
      Label found(this), found_fast(this), found_dict(this), found_global(this);
      TVARIABLE(HeapObject, var_meta_storage);
      TVARIABLE(IntPtrT, var_entry);
      TryLookupProperty(holder, holder_map, instance_type, name, &found_fast,
                        &found_dict, &found_global, &var_meta_storage,
                        &var_entry, &next_proto, bailout);
      BIND(&found_fast);
      {
        TNode<DescriptorArray> descriptors = CAST(var_meta_storage.value());
        TNode<IntPtrT> name_index = var_entry.value();
        TNode<Uint32T> details = LoadDetailsByKeyIndex(descriptors, name_index);
        JumpIfDataProperty(details, &ok_to_write, readonly);

        // Accessor case.
        // TODO(jkummerow): Implement a trimmed-down
        // LoadAccessorFromFastObject.
        LoadPropertyFromFastObject(holder, holder_map, descriptors, name_index,
                                   details, var_accessor_pair);
        *var_accessor_holder = holder;
        Goto(accessor);
      }

      BIND(&found_dict);
      {
        TNode<PropertyDictionary> dictionary = CAST(var_meta_storage.value());
        TNode<IntPtrT> entry = var_entry.value();
        TNode<Uint32T> details = LoadDetailsByKeyIndex(dictionary, entry);
        JumpIfDataProperty(details, &ok_to_write, readonly);

        if (accessor != nullptr) {
          // Accessor case.
          *var_accessor_pair = LoadValueByKeyIndex(dictionary, entry);
          *var_accessor_holder = holder;
          Goto(accessor);
        } else {
          Goto(&ok_to_write);
        }
      }

      BIND(&found_global);
      {
        TNode<GlobalDictionary> dictionary = CAST(var_meta_storage.value());
        TNode<IntPtrT> entry = var_entry.value();
        TNode<PropertyCell> property_cell =
            CAST(LoadValueByKeyIndex(dictionary, entry));
        TNode<Object> value =
            LoadObjectField(property_cell, PropertyCell::kValueOffset);
        GotoIf(TaggedEqual(value, TheHoleConstant()
"""


```