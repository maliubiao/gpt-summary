Response:
The user wants a summary of the provided C++ code snippet from V8's `builtins-array-gen.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the File Type:** The prompt explicitly asks if the file ends with `.tq`. Since it doesn't, it's not a Torque file. This is crucial for understanding the code's nature. It's C++ code using V8's internal APIs and macros.

2. **Scan for Core Functionality:**  Look for class names, function names, and key operations. The presence of `ArrayBuiltinsAssembler`, `TypedArrayMapProcessor`, `ArrayPrototypePop`, `ArrayPrototypePush`, and `ArrayIncludesIndexofAssembler` strongly suggests the file deals with implementing built-in array methods.

3. **Group Related Functionality:**  Notice the functions seem to fall into categories:
    * **Typed Arrays:** `TypedArrayMapResultGenerator`, `TypedArrayMapProcessor`, `GenerateIteratingTypedArrayBuiltinBody`, `VisitAllTypedArrayElements`, `TypedArrayPrototypeMap`.
    * **Standard Arrays:** `ArrayPrototypePop`, `ArrayPrototypePush`, `ExtractFastJSArray`, `CloneFastJSArray`, `CloneFastJSArrayFillingHoles`.
    * **Array-like Objects:** `ConstructArrayLike`.
    * **Searching Arrays:** `ArrayIncludesIndexofAssembler`.

4. **Infer High-Level Goals:** The names of the functions strongly suggest their purpose: `Pop` removes an element, `Push` adds elements, `Map` transforms elements, `Includes` and `IndexOf` search for elements, etc. The "fast" versions suggest optimizations for common cases.

5. **Check for JavaScript Relevance:**  Since these are "built-ins," they directly correspond to JavaScript array methods. This allows for clear JavaScript examples.

6. **Address Code Logic and Input/Output (for `TypedArrayMapProcessor` as requested):**  This function processes the result of a callback function on a TypedArray element. The input is the element value, the element index, and the TypedArray itself. The output is the modified TypedArray. A simple example of mapping each element to its square is a good illustration.

7. **Consider Common Errors:**  Think about how developers might misuse these methods in JavaScript. `Pop` and `Push` on non-array objects, or `Map` with a non-callable callback are common errors. Detached TypedArrays are a specific error scenario for TypedArray operations.

8. **Structure the Output:** Organize the information logically, addressing each point from the prompt. Start with the file type and general purpose, then detail specific functionalities. Use headings and bullet points for clarity. Provide JavaScript examples and error scenarios.

9. **Refine and Elaborate:**  Review the generated summary and add details or explanations where necessary. For example, explain *why* there are fast paths (optimization). Mention the role of Torque (even though this specific file isn't Torque, the prompt asked about it).

10. **Address the "Part 1" Request:** Conclude with a summary of the overall function of the file.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "This file just has array methods."  **Correction:**  Realized it's specifically *built-in* implementations, likely performance-critical.
* **Initial thought:** "Just list all the functions." **Correction:** Grouping functions by category makes the summary more understandable.
* **Initial thought:** "The code is too low-level for a good JavaScript example." **Correction:** Focus on the *effect* of the built-in methods in JavaScript, rather than the C++ implementation details.
* **Initial thought:**  "Just provide the code logic as-is." **Correction:** The prompt asks for *inferred* input and output. A clear example is better than just restating the function's steps.

By following this thought process, combining code analysis with understanding of JavaScript's array functionality, the detailed and accurate summary can be generated.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-array-gen.h"

#include <optional>

#include "src/builtins/builtins-constructor-gen.h"
#include "src/builtins/builtins-constructor.h"
#include "src/builtins/builtins-iterator-gen.h"
#include "src/builtins/builtins-string-gen.h"
#include "src/builtins/builtins-typed-array-gen.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/tnode.h"
#include "src/execution/frame-constants.h"
#include "src/heap/factory-inl.h"
#include "src/objects/allocation-site-inl.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/elements-kind.h"
#include "src/objects/property-cell.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

ArrayBuiltinsAssembler::ArrayBuiltinsAssembler(
    compiler::CodeAssemblerState* state)
    : CodeStubAssembler(state),
      k_(this),
      a_(this),
      fully_spec_compliant_(this, {&k_, &a_}) {}

void ArrayBuiltinsAssembler::TypedArrayMapResultGenerator() {
  // 6. Let A be ? TypedArraySpeciesCreate(O, len).
  TNode<JSTypedArray> original_array = CAST(o());
  const char* method_name = "%TypedArray%.prototype.map";

  TNode<JSTypedArray> a = TypedArraySpeciesCreateByLength(
      context(), method_name, original_array, len());
  // In the Spec and our current implementation, the length check is already
  // performed in TypedArraySpeciesCreate.
#ifdef DEBUG
  Label detached_or_out_of_bounds(this), done(this);
  CSA_DCHECK(this, UintPtrLessThanOrEqual(
                       len(), LoadJSTypedArrayLengthAndCheckDetached(
                                  a, &detached_or_out_of_bounds)));
  Goto(&done);
  BIND(&detached_or_out_of_bounds);
  Unreachable();
  BIND(&done);
#endif  // DEBUG

  // TODO(v8:11111): Make storing fast when the elements kinds only differ
  // because of their RAB/GSABness.
  fast_typed_array_target_ =
      Word32Equal(LoadElementsKind(original_array), LoadElementsKind(a));
  a_ = a;
}

// See tc39.github.io/ecma262/#sec-%typedarray%.prototype.map.
TNode<Object> ArrayBuiltinsAssembler::TypedArrayMapProcessor(
    TNode<Object> k_value, TNode<UintPtrT> k) {
  // 7c. Let mapped_value be ? Call(callbackfn, T, « kValue, k, O »).
  TNode<Number> k_number = ChangeUintPtrToTagged(k);
  TNode<Object> mapped_value =
      Call(context(), callbackfn(), this_arg(), k_value, k_number, o());
  Label fast(this), slow(this), done(this), detached(this, Label::kDeferred);

  // 7d. Perform ? Set(A, Pk, mapped_value, true).
  // Since we know that A is a TypedArray, this always ends up in
  // #sec-integer-indexed-exotic-objects-set-p-v-receiver and then
  // tc39.github.io/ecma262/#sec-integerindexedelementset .
  Branch(fast_typed_array_target_, &fast, &slow);

  BIND(&fast);
  // #sec-integerindexedelementset
  // 2. If arrayTypeName is "BigUint64Array" or "BigInt64Array", let
  // numValue be ? ToBigInt(v).
  // 3. Otherwise, let numValue be ? ToNumber(value).
  TNode<Object> num_value;
  if (IsBigIntTypedArrayElementsKind(source_elements_kind_)) {
    num_value = ToBigInt(context(), mapped_value);
  } else {
    num_value = ToNumber_Inline(context(), mapped_value);
  }

  // The only way how this can bailout is because of a detached or out of bounds
  // buffer.
  // TODO(v8:4153): Consider checking IsDetachedBuffer() and calling
  // TypedArrayBuiltinsAssembler::StoreJSTypedArrayElementFromNumeric() here
  // instead to avoid converting k_number back to UintPtrT.

  // Using source_elements_kind_ (not "target elements kind") is correct here,
  // because the fast branch is taken only when the source and the target
  // elements kinds match.
  EmitElementStore(CAST(a()), k_number, num_value, source_elements_kind_,
                   KeyedAccessStoreMode::kInBounds, &detached, context());
  Goto(&done);

  BIND(&slow);
  {
    SetPropertyStrict(context(), a(), k_number, mapped_value);
    Goto(&done);
  }

  BIND(&detached);
  // tc39.github.io/ecma262/#sec-integerindexedelementset
  // 8. If IsDetachedBuffer(buffer) is true, throw a TypeError exception.
  ThrowTypeError(context_, MessageTemplate::kDetachedOperation, name_);

  BIND(&done);
  return a();
}

void ArrayBuiltinsAssembler::ReturnFromBuiltin(TNode<Object> value) {
  if (argc_ == nullptr) {
    Return(value);
  } else {
    CodeStubArguments args(this, argc());
    PopAndReturn(args.GetLengthWithReceiver(), value);
  }
}

void ArrayBuiltinsAssembler::InitIteratingArrayBuiltinBody(
    TNode<Context> context, TNode<Object> receiver, TNode<Object> callbackfn,
    TNode<Object> this_arg, TNode<IntPtrT> argc) {
  context_ = context;
  receiver_ = receiver;
  callbackfn_ = callbackfn;
  this_arg_ = this_arg;
  argc_ = argc;
}

void ArrayBuiltinsAssembler::GenerateIteratingTypedArrayBuiltinBody(
    const char* name, const BuiltinResultGenerator& generator,
    const CallResultProcessor& processor, ForEachDirection direction) {
  name_ = name;

  // ValidateTypedArray: tc39.github.io/ecma262/#sec-validatetypedarray

  Label throw_not_typed_array(this, Label::kDeferred);

  GotoIf(TaggedIsSmi(receiver_), &throw_not_typed_array);
  TNode<Map> typed_array_map = LoadMap(CAST(receiver_));
  GotoIfNot(IsJSTypedArrayMap(typed_array_map), &throw_not_typed_array);

  TNode<JSTypedArray> typed_array = CAST(receiver_);
  o_ = typed_array;

  Label throw_detached(this, Label::kDeferred);
  len_ = LoadJSTypedArrayLengthAndCheckDetached(typed_array, &throw_detached);

  Label throw_not_callable(this, Label::kDeferred);
  Label distinguish_types(this);
  GotoIf(TaggedIsSmi(callbackfn_), &throw_not_callable);
  Branch(IsCallableMap(LoadMap(CAST(callbackfn_))), &distinguish_types,
         &throw_not_callable);

  BIND(&throw_not_typed_array);
  ThrowTypeError(context_, MessageTemplate::kNotTypedArray);

  BIND(&throw_not_callable);
  ThrowTypeError(context_, MessageTemplate::kCalledNonCallable, callbackfn_);

  BIND(&throw_detached);
  ThrowTypeError(context_, MessageTemplate::kDetachedOperation, name_);

  Label unexpected_instance_type(this);
  BIND(&unexpected_instance_type);
  Unreachable();

  std::vector<int32_t> elements_kinds = {
#define ELEMENTS_KIND(Type, type, TYPE, ctype) TYPE##_ELEMENTS,
      TYPED_ARRAYS(ELEMENTS_KIND) RAB_GSAB_TYPED_ARRAYS(ELEMENTS_KIND)
#undef ELEMENTS_KIND
  };
  std::list<Label> labels;
  for (size_t i = 0; i < elements_kinds.size(); ++i) {
    labels.emplace_back(this);
  }
  std::vector<Label*> label_ptrs;
  for (Label& label : labels) {
    label_ptrs.push_back(&label);
  }

  BIND(&distinguish_types);

  generator(this);

  TNode<JSArrayBuffer> array_buffer = LoadJSArrayBufferViewBuffer(typed_array);
  TNode<Int32T> elements_kind = LoadMapElementsKind(typed_array_map);
  Switch(elements_kind, &unexpected_instance_type, elements_kinds.data(),
         label_ptrs.data(), labels.size());

  size_t i = 0;
  for (auto it = labels.begin(); it != labels.end(); ++i, ++it) {
    BIND(&*it);
    source_elements_kind_ = static_cast<ElementsKind>(elements_kinds[i]);
    VisitAllTypedArrayElements(array_buffer, processor, direction, typed_array);
    ReturnFromBuiltin(a_.value());
  }
}

void ArrayBuiltinsAssembler::VisitAllTypedArrayElements(
    TNode<JSArrayBuffer> array_buffer, const CallResultProcessor& processor,
    ForEachDirection direction, TNode<JSTypedArray> typed_array) {
  VariableList list({&a_, &k_}, zone());

  TNode<UintPtrT> start = UintPtrConstant(0);
  TNode<UintPtrT> end = len_;
  IndexAdvanceMode advance_mode = IndexAdvanceMode::kPost;
  int incr = 1;
  if (direction == ForEachDirection::kReverse) {
    std::swap(start, end);
    advance_mode = IndexAdvanceMode::kPre;
    incr = -1;
  }
  k_ = start;

  // TODO(v8:11111): Only RAB-backed TAs need special handling here since the
  // backing store can shrink mid-iteration. This implementation has an
  // overzealous check for GSAB-backed length-tracking TAs. Then again, the
  // non-RAB/GSAB code also has an overzealous detached check for SABs.
  ElementsKind effective_elements_kind = source_elements_kind_;
  bool is_rab_gsab = IsRabGsabTypedArrayElementsKind(effective_elements_kind);
  if (is_rab_gsab) {
    effective_elements_kind =
        GetCorrespondingNonRabGsabElementsKind(effective_elements_kind);
  }
  BuildFastLoop<UintPtrT>(
      list, start, end,
      [&](TNode<UintPtrT> index) {
        TVARIABLE(Object, value);
        Label detached(this, Label::kDeferred);
        Label process(this);
        if (is_rab_gsab) {
          // If `index` is out of bounds, Get returns undefined.
          CheckJSTypedArrayIndex(typed_array, index, &detached);
        } else {
          GotoIf(IsDetachedBuffer(array_buffer), &detached);
        }
        {
          TNode<RawPtrT> data_ptr = LoadJSTypedArrayDataPtr(typed_array);
          value = LoadFixedTypedArrayElementAsTagged(data_ptr, index,
                                                     effective_elements_kind);
          Goto(&process);
        }

        BIND(&detached);
        {
          value = UndefinedConstant();
          Goto(&process);
        }

        BIND(&process);
        {
          k_ = index;
          a_ = processor(this, value.value(), index);
        }
      },
      incr, LoopUnrollingMode::kNo, advance_mode);
}

TF_BUILTIN(ArrayPrototypePop, CodeStubAssembler) {
  auto argc = UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
  auto context = Parameter<Context>(Descriptor::kContext);
  CSA_DCHECK(this, IsUndefined(Parameter<Object>(Descriptor::kJSNewTarget)));

  CodeStubArguments args(this, argc);
  TNode<Object> receiver = args.GetReceiver();

  Label runtime(this, Label::kDeferred);
  Label fast(this);

  // Only pop in this stub if
  // 1) the array has fast elements
  // 2) the length is writable,
  // 3) the elements backing store isn't copy-on-write,
  // 4) we aren't supposed to shrink the backing store.

  // 1) Check that the array has fast elements.
  BranchIfFastJSArray(receiver, context, &fast, &runtime);

  BIND(&fast);
  {
    TNode<JSArray> array_receiver = CAST(receiver);
    CSA_DCHECK(this, TaggedIsPositiveSmi(LoadJSArrayLength(array_receiver)));
    TNode<Int32T> length =
        LoadAndUntagToWord32ObjectField(array_receiver, JSArray::kLengthOffset);
    Label return_undefined(this), fast_elements(this);

    // 2) Ensure that the length is writable.
    EnsureArrayLengthWritable(context, LoadMap(array_receiver), &runtime);

    GotoIf(Word32Equal(length, Int32Constant(0)), &return_undefined);

    // 3) Check that the elements backing store isn't copy-on-write.
    TNode<FixedArrayBase> elements = LoadElements(array_receiver);
    GotoIf(TaggedEqual(LoadMap(elements), FixedCOWArrayMapConstant()),
           &runtime);

    TNode<Int32T> new_length = Int32Sub(length, Int32Constant(1));

    // 4) Check that we're not supposed to shrink the backing store, as
    //    implemented in elements.cc:ElementsAccessorBase::SetLengthImpl.
    TNode<Int32T> capacity = SmiToInt32(LoadFixedArrayBaseLength(elements));
    GotoIf(Int32LessThan(
               Int32Add(Int32Add(new_length, new_length),
                        Int32Constant(JSObject::kMinAddedElementsCapacity)),
               capacity),
           &runtime);

    TNode<IntPtrT> new_length_intptr = ChangePositiveInt32ToIntPtr(new_length);
    StoreObjectFieldNoWriteBarrier(array_receiver, JSArray::kLengthOffset,
                                   SmiTag(new_length_intptr));

    TNode<Int32T> elements_kind = LoadElementsKind(array_receiver);
    GotoIf(Int32LessThanOrEqual(elements_kind,
                                Int32Constant(TERMINAL_FAST_ELEMENTS_KIND)),
           &fast_elements);

    {
      TNode<FixedDoubleArray> elements_known_double_array =
          ReinterpretCast<FixedDoubleArray>(elements);
      TNode<Float64T> value = LoadFixedDoubleArrayElement(
          elements_known_double_array, new_length_intptr, &return_undefined);

      StoreFixedDoubleArrayHole(elements_known_double_array, new_length_intptr);
      args.PopAndReturn(AllocateHeapNumberWithValue(value));
    }

    BIND(&fast_elements);
    {
      TNode<FixedArray> elements_known_fixed_array = CAST(elements);
      TNode<Object> value =
          LoadFixedArrayElement(elements_known_fixed_array, new_length_intptr);
      StoreFixedArrayElement(elements_known_fixed_array, new_length_intptr,
                             TheHoleConstant());
      GotoIf(TaggedEqual(value, TheHoleConstant()), &return_undefined);
      args.PopAndReturn(value);
    }

    BIND(&return_undefined);
    { args.PopAndReturn(UndefinedConstant()); }
  }

  BIND(&runtime);
  {
    // We are not using Parameter(Descriptor::kJSTarget) and loading the value
    // from the current frame here in order to reduce register pressure on the
    // fast path.
    TNode<JSFunction> target = LoadTargetFromFrame();
    TailCallJSBuiltin(Builtin::kArrayPop, context, target, UndefinedConstant(),
                      argc, InvalidDispatchHandleConstant());
  }
}

TF_BUILTIN(ArrayPrototypePush, CodeStubAssembler) {
  TVARIABLE(IntPtrT, arg_index);
  Label default_label(this, &arg_index);
  Label smi_transition(this);
  Label object_push_pre(this);
  Label object_push(this, &arg_index);
  Label double_push(this, &arg_index);
  Label double_transition(this);
  Label runtime(this, Label::kDeferred);

  auto argc = UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
  auto context = Parameter<Context>(Descriptor::kContext);
  CSA_DCHECK(this, IsUndefined(Parameter<Object>(Descriptor::kJSNewTarget)));

  CodeStubArguments args(this, argc);
  TNode<Object> receiver = args.GetReceiver();
  TNode<JSArray> array_receiver;
  TNode<Int32T> kind;

  Label fast(this);
  BranchIfFastJSArray(receiver, context, &fast, &runtime);

  BIND(&fast);
  {
    array_receiver = CAST(receiver);
    arg_index = IntPtrConstant(0);
    kind = EnsureArrayPushable(context, LoadMap(array_receiver), &runtime);
    GotoIf(IsElementsKindGreaterThan(kind, HOLEY_SMI_ELEMENTS),
           &object_push_pre);

    TNode<Smi> new_length =
        BuildAppendJSArray(PACKED_SMI_ELEMENTS, array_receiver, &args,
                           &arg_index, &smi_transition);
    args.PopAndReturn(new_length);
  }

  // If the argument is not a smi, then use a heavyweight SetProperty to
  // transition the array for only the single next element. If the argument is
  // a smi, the failure is due to some other reason and we should fall back on
  // the most generic implementation for the rest of the array.
  BIND(&smi_transition);
  {
    TNode<Object> arg = args.AtIndex(arg_index.value());
    GotoIf(TaggedIsSmi(arg), &default_label);
    TNode<Number> length = LoadJSArrayLength(array_receiver);
    // TODO(danno): Use the KeyedStoreGeneric stub here when possible,
    // calling into the runtime to do the elements transition is overkill.
    SetPropertyStrict(context, array_receiver, length, arg);
    Increment(&arg_index);
    // The runtime SetProperty call could have converted the array to dictionary
    // mode, which must be detected to abort the fast-path.
    TNode<Int32T> elements_kind = LoadElementsKind(array_receiver);
    GotoIf(Word32Equal(elements_kind, Int32Constant(DICTIONARY_ELEMENTS)),
           &default_label);

    GotoIfNotNumber(arg, &object_push);
    Goto(&double_push);
  }

  BIND(&object_push_pre);
  {
    Branch(IsElementsKindGreaterThan(kind, HOLEY_ELEMENTS), &double_push,
           &object_push);
  }

  BIND(&object_push);
  {
    TNode<Smi> new_length = BuildAppendJSArray(
        PACKED_ELEMENTS, array_receiver, &args, &arg_index, &default_label);
    args.PopAndReturn(new_length);
  }

  BIND(&double_push);
  {
    TNode<Smi> new_length =
        BuildAppendJSArray(PACKED_DOUBLE_ELEMENTS, array_receiver, &args,
                           &arg_index, &double_transition);
    args.PopAndReturn(new_length);
  }

  // If the argument is not a double, then use a heavyweight SetProperty to
  // transition the array for only the single next element. If the argument is
  // a double, the failure is due to some other reason and we should fall back
  // on the most generic implementation for the rest of the array.
  BIND(&double_transition);
  {
    TNode<Object> arg = args.AtIndex(arg_index.value());
    GotoIfNumber(arg, &default_label);
    TNode<Number> length = LoadJSArrayLength(array_receiver);
    // TODO(danno): Use the KeyedStoreGeneric stub here when possible,
    // calling into the runtime to do the elements transition is overkill.
    SetPropertyStrict(context, array_receiver, length, arg);
    Increment(&arg_index);
    // The runtime SetProperty call could have converted the array to dictionary
    // mode, which must be detected to abort the fast-path.
    TNode<Int32T> elements_kind = LoadElementsKind(array_receiver);
    GotoIf(Word32Equal(elements_kind, Int32Constant(DICTIONARY_ELEMENTS)),
           &default_label);
    Goto(&object_push);
  }

  // Fallback that stores un-processed arguments using the full, heavyweight
  // SetProperty machinery.
  BIND(&default_label);
  {
    args.ForEach(
        [=, this](TNode<Object> arg) {
          TNode<Number> length = LoadJSArrayLength(array_receiver);
          SetPropertyStrict(context, array_receiver, length, arg);
        },
        arg_index.value());
    args.PopAndReturn(LoadJSArrayLength(array_receiver));
  }

  BIND(&runtime);
  {
    // We are not using Parameter(Descriptor::kJSTarget) and loading the value
    // from the current frame here in order to reduce register pressure on the
    // fast path.
    TNode<JSFunction> target = LoadTargetFromFrame();
    TailCallJSBuiltin(Builtin::kArrayPush, context, target, UndefinedConstant(),
                      argc, InvalidDispatchHandleConstant());
  }
}

TF_BUILTIN(ExtractFastJSArray, ArrayBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto array = Parameter<JSArray>(Descriptor::kSource);
  TNode<BInt> begin = SmiToBInt(Parameter<Smi>(Descriptor::kBegin));
  TNode<BInt> count = SmiToBInt(Parameter<Smi>(Descriptor::kCount));

  CSA_DCHECK(this, Word32BinaryNot(IsNoElementsProtectorCellInvalid()));

  Return(ExtractFastJSArray(context, array, begin, count));
}

TF_BUILTIN(CloneFastJSArray, ArrayBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto array = Parameter<JSArray>(Descriptor::kSource);

  CSA_DCHECK(this,
             Word32Or(Word32BinaryNot(IsHoleyFastElementsKindForRead(
                          LoadElementsKind(array))),
                      Word32BinaryNot(IsNoElementsProtectorCellInvalid())));

  Return(CloneFastJSArray(context, array));
}

// This builtin copies the backing store of fast arrays, while converting any
// holes to undefined.
// - If there are no holes in the source, its ElementsKind will be preserved. In
// that case, this builtin should perform as fast as CloneFastJSArray. (In fact,
// for fast packed arrays, the behavior is equivalent to CloneFastJSArray.)
// - If there are holes in the source, the ElementsKind of the "copy" will be
// PACKED_ELEMENTS (such that undefined can be stored).
TF_BUILTIN(CloneFastJSArrayFillingHoles, ArrayBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto array = Parameter<JSArray>(Descriptor::kSource);

  CSA_DCHECK(this,
             Word32Or(Word32BinaryNot(IsHoleyFastElementsKindForRead(
                          LoadElementsKind(array))),
                      Word32BinaryNot(IsNoElementsProtectorCellInvalid())));

  Return(CloneFastJSArray(context, array, std::nullopt,
                          HoleConversionMode::kConvertToUndefined));
}

class ArrayPopulatorAssembler : public CodeStubAssembler {
 public:
  explicit ArrayPopulatorAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  TNode<Object> ConstructArrayLike(TNode<Context> context,
                                   TNode<Object> receiver) {
    TVARIABLE(Object, array);
    Label is_constructor(this), is_not_constructor(this), done(this);
    GotoIf(TaggedIsSmi(receiver), &is_not_constructor);
    Branch(IsConstructor(CAST(receiver)), &is_constructor, &is_not_constructor);

    BIND(&is_constructor);
    {
      array = Construct(context, CAST(receiver));
      Goto(&done);
    }

    BIND(&is_not_constructor);
    {
      Label allocate_js_array(this);

      TNode<Map> array_map = CAST(LoadContextElement(
          context, Context::JS_ARRAY_PACKED_SMI_ELEMENTS_MAP_INDEX));

      TNode<IntPtrT> capacity = IntPtrConstant(0);
      TNode<Smi> length = SmiConstant(0);
      array = AllocateJSArray(PACKED_SMI_ELEMENTS, array_map, capacity, length);
      Goto(&done);
    }

    BIND(&done);
    return array.value();
  }

  TNode<Object> ConstructArrayLike(TNode<Context> context,
                                   TNode<Object> receiver,
                                   TNode<Number> length) {
    TVARIABLE(Object, array);
    Label is_constructor(this), is_not_constructor(this), done(this);
    CSA_DCHECK(this, IsNumberNormalized(length));
    GotoIf(TaggedIsSmi(receiver), &is_not_constructor);
    Branch(IsConstructor(CAST(receiver)), &is_constructor, &is_not_constructor);

    BIND(&is_constructor);
    {
      array = Construct(context, CAST(receiver), length);
      Goto(&done);
    }

    BIND(&is_not_constructor);
    {
      array = ArrayCreate(context, length);
      Goto(&done);
    }

    BIND(&done);
    return array.value();
  }
};

TF_BUILTIN(TypedArrayPrototypeMap, ArrayBuiltinsAssembler) {
  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  CodeStubArguments args(this, argc);
  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<Object> receiver = args.GetReceiver();
  TNode<Object> callbackfn = args.GetOptionalArgumentValue(0);
  TNode<Object> this_arg = args.GetOptionalArgumentValue(1);

  InitIteratingArrayBuiltinBody(context, receiver, callbackfn, this_arg, argc);

  GenerateIteratingTypedArrayBuiltinBody(
      "%TypedArray%.prototype.map",
      &ArrayBuiltinsAssembler::TypedArrayMapResultGenerator,
      &ArrayBuiltinsAssembler::TypedArrayMapProcessor);
}

class ArrayIncludesIndexofAssembler : public CodeStubAssembler {
 public:
  explicit ArrayIncludesIndexofAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  enum SearchVariant { kIncludes, kIndexOf };

  enum class SimpleElementKind { kSmiOrHole, kAny };

  void Generate(SearchVariant variant, TNode<IntPtrT> argc,
                TNode<Context> context);
  void GenerateSmiOrObject(SearchVariant variant, TNode<Context> context,
                           TNode<FixedArray> elements,
                           TNode<Object> search_element,
                           TNode<Smi> array_length, TNode<Smi> from_index,
                           SimpleElementKind array_kind);
  void GeneratePackedDoubles(SearchVariant variant,
                             TNode<FixedDoubleArray> elements,
                             TNode<Object> search_element,
                             TNode<Smi> array_length, TNode<Smi> from_index);
  void GenerateHoleyDoubles(SearchVariant variant,
                            TNode<FixedDoubleArray> elements,
                            TNode<Object> search_element,
                            TNode<Smi> array_length, TNode<Smi> from_index);

  void ReturnIfEmpty(TNode<Smi> length, TNode<Object> value) {
    Label done(this);
    GotoIf(SmiGreaterThan(length, SmiConstant(0)), &done);
    Return(value);
    BIND(&done);
  }

 private:
  // Use SIMD code for arrays larger than kSIMDThreshold (in builtins that have
  // SIMD implementations).
  const int kSIMDThreshold = 48;

  // For now, we can vectorize if:
  //   - SSE3/AVX are present (x86/x64). Note that if __AVX__ is defined, then
  //     __SSE3__ will be as well, so we just check __SSE3__.
  //   - Neon is present and the architecture is 64-bit (because Neon on 32-bit
  //     architecture lacks some instructions).
#if defined(__SSE3__) || defined(V8_HOST_ARCH_ARM64)
  const bool kCanVectorize = true;
#else
  const bool kCanVectorize = false;
#endif
};

void ArrayIncludesIndexofAssembler::Generate
### 提示词
```
这是目录为v8/src/builtins/builtins-array-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-array-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-array-gen.h"

#include <optional>

#include "src/builtins/builtins-constructor-gen.h"
#include "src/builtins/builtins-constructor.h"
#include "src/builtins/builtins-iterator-gen.h"
#include "src/builtins/builtins-string-gen.h"
#include "src/builtins/builtins-typed-array-gen.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/tnode.h"
#include "src/execution/frame-constants.h"
#include "src/heap/factory-inl.h"
#include "src/objects/allocation-site-inl.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/elements-kind.h"
#include "src/objects/property-cell.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

ArrayBuiltinsAssembler::ArrayBuiltinsAssembler(
    compiler::CodeAssemblerState* state)
    : CodeStubAssembler(state),
      k_(this),
      a_(this),
      fully_spec_compliant_(this, {&k_, &a_}) {}

void ArrayBuiltinsAssembler::TypedArrayMapResultGenerator() {
  // 6. Let A be ? TypedArraySpeciesCreate(O, len).
  TNode<JSTypedArray> original_array = CAST(o());
  const char* method_name = "%TypedArray%.prototype.map";

  TNode<JSTypedArray> a = TypedArraySpeciesCreateByLength(
      context(), method_name, original_array, len());
  // In the Spec and our current implementation, the length check is already
  // performed in TypedArraySpeciesCreate.
#ifdef DEBUG
  Label detached_or_out_of_bounds(this), done(this);
  CSA_DCHECK(this, UintPtrLessThanOrEqual(
                       len(), LoadJSTypedArrayLengthAndCheckDetached(
                                  a, &detached_or_out_of_bounds)));
  Goto(&done);
  BIND(&detached_or_out_of_bounds);
  Unreachable();
  BIND(&done);
#endif  // DEBUG

  // TODO(v8:11111): Make storing fast when the elements kinds only differ
  // because of their RAB/GSABness.
  fast_typed_array_target_ =
      Word32Equal(LoadElementsKind(original_array), LoadElementsKind(a));
  a_ = a;
}

// See tc39.github.io/ecma262/#sec-%typedarray%.prototype.map.
TNode<Object> ArrayBuiltinsAssembler::TypedArrayMapProcessor(
    TNode<Object> k_value, TNode<UintPtrT> k) {
  // 7c. Let mapped_value be ? Call(callbackfn, T, « kValue, k, O »).
  TNode<Number> k_number = ChangeUintPtrToTagged(k);
  TNode<Object> mapped_value =
      Call(context(), callbackfn(), this_arg(), k_value, k_number, o());
  Label fast(this), slow(this), done(this), detached(this, Label::kDeferred);

  // 7d. Perform ? Set(A, Pk, mapped_value, true).
  // Since we know that A is a TypedArray, this always ends up in
  // #sec-integer-indexed-exotic-objects-set-p-v-receiver and then
  // tc39.github.io/ecma262/#sec-integerindexedelementset .
  Branch(fast_typed_array_target_, &fast, &slow);

  BIND(&fast);
  // #sec-integerindexedelementset
  // 2. If arrayTypeName is "BigUint64Array" or "BigInt64Array", let
  // numValue be ? ToBigInt(v).
  // 3. Otherwise, let numValue be ? ToNumber(value).
  TNode<Object> num_value;
  if (IsBigIntTypedArrayElementsKind(source_elements_kind_)) {
    num_value = ToBigInt(context(), mapped_value);
  } else {
    num_value = ToNumber_Inline(context(), mapped_value);
  }

  // The only way how this can bailout is because of a detached or out of bounds
  // buffer.
  // TODO(v8:4153): Consider checking IsDetachedBuffer() and calling
  // TypedArrayBuiltinsAssembler::StoreJSTypedArrayElementFromNumeric() here
  // instead to avoid converting k_number back to UintPtrT.

  // Using source_elements_kind_ (not "target elements kind") is correct here,
  // because the fast branch is taken only when the source and the target
  // elements kinds match.
  EmitElementStore(CAST(a()), k_number, num_value, source_elements_kind_,
                   KeyedAccessStoreMode::kInBounds, &detached, context());
  Goto(&done);

  BIND(&slow);
  {
    SetPropertyStrict(context(), a(), k_number, mapped_value);
    Goto(&done);
  }

  BIND(&detached);
  // tc39.github.io/ecma262/#sec-integerindexedelementset
  // 8. If IsDetachedBuffer(buffer) is true, throw a TypeError exception.
  ThrowTypeError(context_, MessageTemplate::kDetachedOperation, name_);

  BIND(&done);
  return a();
}

void ArrayBuiltinsAssembler::ReturnFromBuiltin(TNode<Object> value) {
  if (argc_ == nullptr) {
    Return(value);
  } else {
    CodeStubArguments args(this, argc());
    PopAndReturn(args.GetLengthWithReceiver(), value);
  }
}

void ArrayBuiltinsAssembler::InitIteratingArrayBuiltinBody(
    TNode<Context> context, TNode<Object> receiver, TNode<Object> callbackfn,
    TNode<Object> this_arg, TNode<IntPtrT> argc) {
  context_ = context;
  receiver_ = receiver;
  callbackfn_ = callbackfn;
  this_arg_ = this_arg;
  argc_ = argc;
}

void ArrayBuiltinsAssembler::GenerateIteratingTypedArrayBuiltinBody(
    const char* name, const BuiltinResultGenerator& generator,
    const CallResultProcessor& processor, ForEachDirection direction) {
  name_ = name;

  // ValidateTypedArray: tc39.github.io/ecma262/#sec-validatetypedarray

  Label throw_not_typed_array(this, Label::kDeferred);

  GotoIf(TaggedIsSmi(receiver_), &throw_not_typed_array);
  TNode<Map> typed_array_map = LoadMap(CAST(receiver_));
  GotoIfNot(IsJSTypedArrayMap(typed_array_map), &throw_not_typed_array);

  TNode<JSTypedArray> typed_array = CAST(receiver_);
  o_ = typed_array;

  Label throw_detached(this, Label::kDeferred);
  len_ = LoadJSTypedArrayLengthAndCheckDetached(typed_array, &throw_detached);

  Label throw_not_callable(this, Label::kDeferred);
  Label distinguish_types(this);
  GotoIf(TaggedIsSmi(callbackfn_), &throw_not_callable);
  Branch(IsCallableMap(LoadMap(CAST(callbackfn_))), &distinguish_types,
         &throw_not_callable);

  BIND(&throw_not_typed_array);
  ThrowTypeError(context_, MessageTemplate::kNotTypedArray);

  BIND(&throw_not_callable);
  ThrowTypeError(context_, MessageTemplate::kCalledNonCallable, callbackfn_);

  BIND(&throw_detached);
  ThrowTypeError(context_, MessageTemplate::kDetachedOperation, name_);

  Label unexpected_instance_type(this);
  BIND(&unexpected_instance_type);
  Unreachable();

  std::vector<int32_t> elements_kinds = {
#define ELEMENTS_KIND(Type, type, TYPE, ctype) TYPE##_ELEMENTS,
      TYPED_ARRAYS(ELEMENTS_KIND) RAB_GSAB_TYPED_ARRAYS(ELEMENTS_KIND)
#undef ELEMENTS_KIND
  };
  std::list<Label> labels;
  for (size_t i = 0; i < elements_kinds.size(); ++i) {
    labels.emplace_back(this);
  }
  std::vector<Label*> label_ptrs;
  for (Label& label : labels) {
    label_ptrs.push_back(&label);
  }

  BIND(&distinguish_types);

  generator(this);

  TNode<JSArrayBuffer> array_buffer = LoadJSArrayBufferViewBuffer(typed_array);
  TNode<Int32T> elements_kind = LoadMapElementsKind(typed_array_map);
  Switch(elements_kind, &unexpected_instance_type, elements_kinds.data(),
         label_ptrs.data(), labels.size());

  size_t i = 0;
  for (auto it = labels.begin(); it != labels.end(); ++i, ++it) {
    BIND(&*it);
    source_elements_kind_ = static_cast<ElementsKind>(elements_kinds[i]);
    VisitAllTypedArrayElements(array_buffer, processor, direction, typed_array);
    ReturnFromBuiltin(a_.value());
  }
}

void ArrayBuiltinsAssembler::VisitAllTypedArrayElements(
    TNode<JSArrayBuffer> array_buffer, const CallResultProcessor& processor,
    ForEachDirection direction, TNode<JSTypedArray> typed_array) {
  VariableList list({&a_, &k_}, zone());

  TNode<UintPtrT> start = UintPtrConstant(0);
  TNode<UintPtrT> end = len_;
  IndexAdvanceMode advance_mode = IndexAdvanceMode::kPost;
  int incr = 1;
  if (direction == ForEachDirection::kReverse) {
    std::swap(start, end);
    advance_mode = IndexAdvanceMode::kPre;
    incr = -1;
  }
  k_ = start;

  // TODO(v8:11111): Only RAB-backed TAs need special handling here since the
  // backing store can shrink mid-iteration. This implementation has an
  // overzealous check for GSAB-backed length-tracking TAs. Then again, the
  // non-RAB/GSAB code also has an overzealous detached check for SABs.
  ElementsKind effective_elements_kind = source_elements_kind_;
  bool is_rab_gsab = IsRabGsabTypedArrayElementsKind(effective_elements_kind);
  if (is_rab_gsab) {
    effective_elements_kind =
        GetCorrespondingNonRabGsabElementsKind(effective_elements_kind);
  }
  BuildFastLoop<UintPtrT>(
      list, start, end,
      [&](TNode<UintPtrT> index) {
        TVARIABLE(Object, value);
        Label detached(this, Label::kDeferred);
        Label process(this);
        if (is_rab_gsab) {
          // If `index` is out of bounds, Get returns undefined.
          CheckJSTypedArrayIndex(typed_array, index, &detached);
        } else {
          GotoIf(IsDetachedBuffer(array_buffer), &detached);
        }
        {
          TNode<RawPtrT> data_ptr = LoadJSTypedArrayDataPtr(typed_array);
          value = LoadFixedTypedArrayElementAsTagged(data_ptr, index,
                                                     effective_elements_kind);
          Goto(&process);
        }

        BIND(&detached);
        {
          value = UndefinedConstant();
          Goto(&process);
        }

        BIND(&process);
        {
          k_ = index;
          a_ = processor(this, value.value(), index);
        }
      },
      incr, LoopUnrollingMode::kNo, advance_mode);
}

TF_BUILTIN(ArrayPrototypePop, CodeStubAssembler) {
  auto argc = UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
  auto context = Parameter<Context>(Descriptor::kContext);
  CSA_DCHECK(this, IsUndefined(Parameter<Object>(Descriptor::kJSNewTarget)));

  CodeStubArguments args(this, argc);
  TNode<Object> receiver = args.GetReceiver();

  Label runtime(this, Label::kDeferred);
  Label fast(this);

  // Only pop in this stub if
  // 1) the array has fast elements
  // 2) the length is writable,
  // 3) the elements backing store isn't copy-on-write,
  // 4) we aren't supposed to shrink the backing store.

  // 1) Check that the array has fast elements.
  BranchIfFastJSArray(receiver, context, &fast, &runtime);

  BIND(&fast);
  {
    TNode<JSArray> array_receiver = CAST(receiver);
    CSA_DCHECK(this, TaggedIsPositiveSmi(LoadJSArrayLength(array_receiver)));
    TNode<Int32T> length =
        LoadAndUntagToWord32ObjectField(array_receiver, JSArray::kLengthOffset);
    Label return_undefined(this), fast_elements(this);

    // 2) Ensure that the length is writable.
    EnsureArrayLengthWritable(context, LoadMap(array_receiver), &runtime);

    GotoIf(Word32Equal(length, Int32Constant(0)), &return_undefined);

    // 3) Check that the elements backing store isn't copy-on-write.
    TNode<FixedArrayBase> elements = LoadElements(array_receiver);
    GotoIf(TaggedEqual(LoadMap(elements), FixedCOWArrayMapConstant()),
           &runtime);

    TNode<Int32T> new_length = Int32Sub(length, Int32Constant(1));

    // 4) Check that we're not supposed to shrink the backing store, as
    //    implemented in elements.cc:ElementsAccessorBase::SetLengthImpl.
    TNode<Int32T> capacity = SmiToInt32(LoadFixedArrayBaseLength(elements));
    GotoIf(Int32LessThan(
               Int32Add(Int32Add(new_length, new_length),
                        Int32Constant(JSObject::kMinAddedElementsCapacity)),
               capacity),
           &runtime);

    TNode<IntPtrT> new_length_intptr = ChangePositiveInt32ToIntPtr(new_length);
    StoreObjectFieldNoWriteBarrier(array_receiver, JSArray::kLengthOffset,
                                   SmiTag(new_length_intptr));

    TNode<Int32T> elements_kind = LoadElementsKind(array_receiver);
    GotoIf(Int32LessThanOrEqual(elements_kind,
                                Int32Constant(TERMINAL_FAST_ELEMENTS_KIND)),
           &fast_elements);

    {
      TNode<FixedDoubleArray> elements_known_double_array =
          ReinterpretCast<FixedDoubleArray>(elements);
      TNode<Float64T> value = LoadFixedDoubleArrayElement(
          elements_known_double_array, new_length_intptr, &return_undefined);

      StoreFixedDoubleArrayHole(elements_known_double_array, new_length_intptr);
      args.PopAndReturn(AllocateHeapNumberWithValue(value));
    }

    BIND(&fast_elements);
    {
      TNode<FixedArray> elements_known_fixed_array = CAST(elements);
      TNode<Object> value =
          LoadFixedArrayElement(elements_known_fixed_array, new_length_intptr);
      StoreFixedArrayElement(elements_known_fixed_array, new_length_intptr,
                             TheHoleConstant());
      GotoIf(TaggedEqual(value, TheHoleConstant()), &return_undefined);
      args.PopAndReturn(value);
    }

    BIND(&return_undefined);
    { args.PopAndReturn(UndefinedConstant()); }
  }

  BIND(&runtime);
  {
    // We are not using Parameter(Descriptor::kJSTarget) and loading the value
    // from the current frame here in order to reduce register pressure on the
    // fast path.
    TNode<JSFunction> target = LoadTargetFromFrame();
    TailCallJSBuiltin(Builtin::kArrayPop, context, target, UndefinedConstant(),
                      argc, InvalidDispatchHandleConstant());
  }
}

TF_BUILTIN(ArrayPrototypePush, CodeStubAssembler) {
  TVARIABLE(IntPtrT, arg_index);
  Label default_label(this, &arg_index);
  Label smi_transition(this);
  Label object_push_pre(this);
  Label object_push(this, &arg_index);
  Label double_push(this, &arg_index);
  Label double_transition(this);
  Label runtime(this, Label::kDeferred);

  auto argc = UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
  auto context = Parameter<Context>(Descriptor::kContext);
  CSA_DCHECK(this, IsUndefined(Parameter<Object>(Descriptor::kJSNewTarget)));

  CodeStubArguments args(this, argc);
  TNode<Object> receiver = args.GetReceiver();
  TNode<JSArray> array_receiver;
  TNode<Int32T> kind;

  Label fast(this);
  BranchIfFastJSArray(receiver, context, &fast, &runtime);

  BIND(&fast);
  {
    array_receiver = CAST(receiver);
    arg_index = IntPtrConstant(0);
    kind = EnsureArrayPushable(context, LoadMap(array_receiver), &runtime);
    GotoIf(IsElementsKindGreaterThan(kind, HOLEY_SMI_ELEMENTS),
           &object_push_pre);

    TNode<Smi> new_length =
        BuildAppendJSArray(PACKED_SMI_ELEMENTS, array_receiver, &args,
                           &arg_index, &smi_transition);
    args.PopAndReturn(new_length);
  }

  // If the argument is not a smi, then use a heavyweight SetProperty to
  // transition the array for only the single next element. If the argument is
  // a smi, the failure is due to some other reason and we should fall back on
  // the most generic implementation for the rest of the array.
  BIND(&smi_transition);
  {
    TNode<Object> arg = args.AtIndex(arg_index.value());
    GotoIf(TaggedIsSmi(arg), &default_label);
    TNode<Number> length = LoadJSArrayLength(array_receiver);
    // TODO(danno): Use the KeyedStoreGeneric stub here when possible,
    // calling into the runtime to do the elements transition is overkill.
    SetPropertyStrict(context, array_receiver, length, arg);
    Increment(&arg_index);
    // The runtime SetProperty call could have converted the array to dictionary
    // mode, which must be detected to abort the fast-path.
    TNode<Int32T> elements_kind = LoadElementsKind(array_receiver);
    GotoIf(Word32Equal(elements_kind, Int32Constant(DICTIONARY_ELEMENTS)),
           &default_label);

    GotoIfNotNumber(arg, &object_push);
    Goto(&double_push);
  }

  BIND(&object_push_pre);
  {
    Branch(IsElementsKindGreaterThan(kind, HOLEY_ELEMENTS), &double_push,
           &object_push);
  }

  BIND(&object_push);
  {
    TNode<Smi> new_length = BuildAppendJSArray(
        PACKED_ELEMENTS, array_receiver, &args, &arg_index, &default_label);
    args.PopAndReturn(new_length);
  }

  BIND(&double_push);
  {
    TNode<Smi> new_length =
        BuildAppendJSArray(PACKED_DOUBLE_ELEMENTS, array_receiver, &args,
                           &arg_index, &double_transition);
    args.PopAndReturn(new_length);
  }

  // If the argument is not a double, then use a heavyweight SetProperty to
  // transition the array for only the single next element. If the argument is
  // a double, the failure is due to some other reason and we should fall back
  // on the most generic implementation for the rest of the array.
  BIND(&double_transition);
  {
    TNode<Object> arg = args.AtIndex(arg_index.value());
    GotoIfNumber(arg, &default_label);
    TNode<Number> length = LoadJSArrayLength(array_receiver);
    // TODO(danno): Use the KeyedStoreGeneric stub here when possible,
    // calling into the runtime to do the elements transition is overkill.
    SetPropertyStrict(context, array_receiver, length, arg);
    Increment(&arg_index);
    // The runtime SetProperty call could have converted the array to dictionary
    // mode, which must be detected to abort the fast-path.
    TNode<Int32T> elements_kind = LoadElementsKind(array_receiver);
    GotoIf(Word32Equal(elements_kind, Int32Constant(DICTIONARY_ELEMENTS)),
           &default_label);
    Goto(&object_push);
  }

  // Fallback that stores un-processed arguments using the full, heavyweight
  // SetProperty machinery.
  BIND(&default_label);
  {
    args.ForEach(
        [=, this](TNode<Object> arg) {
          TNode<Number> length = LoadJSArrayLength(array_receiver);
          SetPropertyStrict(context, array_receiver, length, arg);
        },
        arg_index.value());
    args.PopAndReturn(LoadJSArrayLength(array_receiver));
  }

  BIND(&runtime);
  {
    // We are not using Parameter(Descriptor::kJSTarget) and loading the value
    // from the current frame here in order to reduce register pressure on the
    // fast path.
    TNode<JSFunction> target = LoadTargetFromFrame();
    TailCallJSBuiltin(Builtin::kArrayPush, context, target, UndefinedConstant(),
                      argc, InvalidDispatchHandleConstant());
  }
}

TF_BUILTIN(ExtractFastJSArray, ArrayBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto array = Parameter<JSArray>(Descriptor::kSource);
  TNode<BInt> begin = SmiToBInt(Parameter<Smi>(Descriptor::kBegin));
  TNode<BInt> count = SmiToBInt(Parameter<Smi>(Descriptor::kCount));

  CSA_DCHECK(this, Word32BinaryNot(IsNoElementsProtectorCellInvalid()));

  Return(ExtractFastJSArray(context, array, begin, count));
}

TF_BUILTIN(CloneFastJSArray, ArrayBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto array = Parameter<JSArray>(Descriptor::kSource);

  CSA_DCHECK(this,
             Word32Or(Word32BinaryNot(IsHoleyFastElementsKindForRead(
                          LoadElementsKind(array))),
                      Word32BinaryNot(IsNoElementsProtectorCellInvalid())));

  Return(CloneFastJSArray(context, array));
}

// This builtin copies the backing store of fast arrays, while converting any
// holes to undefined.
// - If there are no holes in the source, its ElementsKind will be preserved. In
// that case, this builtin should perform as fast as CloneFastJSArray. (In fact,
// for fast packed arrays, the behavior is equivalent to CloneFastJSArray.)
// - If there are holes in the source, the ElementsKind of the "copy" will be
// PACKED_ELEMENTS (such that undefined can be stored).
TF_BUILTIN(CloneFastJSArrayFillingHoles, ArrayBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto array = Parameter<JSArray>(Descriptor::kSource);

  CSA_DCHECK(this,
             Word32Or(Word32BinaryNot(IsHoleyFastElementsKindForRead(
                          LoadElementsKind(array))),
                      Word32BinaryNot(IsNoElementsProtectorCellInvalid())));

  Return(CloneFastJSArray(context, array, std::nullopt,
                          HoleConversionMode::kConvertToUndefined));
}

class ArrayPopulatorAssembler : public CodeStubAssembler {
 public:
  explicit ArrayPopulatorAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  TNode<Object> ConstructArrayLike(TNode<Context> context,
                                   TNode<Object> receiver) {
    TVARIABLE(Object, array);
    Label is_constructor(this), is_not_constructor(this), done(this);
    GotoIf(TaggedIsSmi(receiver), &is_not_constructor);
    Branch(IsConstructor(CAST(receiver)), &is_constructor, &is_not_constructor);

    BIND(&is_constructor);
    {
      array = Construct(context, CAST(receiver));
      Goto(&done);
    }

    BIND(&is_not_constructor);
    {
      Label allocate_js_array(this);

      TNode<Map> array_map = CAST(LoadContextElement(
          context, Context::JS_ARRAY_PACKED_SMI_ELEMENTS_MAP_INDEX));

      TNode<IntPtrT> capacity = IntPtrConstant(0);
      TNode<Smi> length = SmiConstant(0);
      array = AllocateJSArray(PACKED_SMI_ELEMENTS, array_map, capacity, length);
      Goto(&done);
    }

    BIND(&done);
    return array.value();
  }

  TNode<Object> ConstructArrayLike(TNode<Context> context,
                                   TNode<Object> receiver,
                                   TNode<Number> length) {
    TVARIABLE(Object, array);
    Label is_constructor(this), is_not_constructor(this), done(this);
    CSA_DCHECK(this, IsNumberNormalized(length));
    GotoIf(TaggedIsSmi(receiver), &is_not_constructor);
    Branch(IsConstructor(CAST(receiver)), &is_constructor, &is_not_constructor);

    BIND(&is_constructor);
    {
      array = Construct(context, CAST(receiver), length);
      Goto(&done);
    }

    BIND(&is_not_constructor);
    {
      array = ArrayCreate(context, length);
      Goto(&done);
    }

    BIND(&done);
    return array.value();
  }
};

TF_BUILTIN(TypedArrayPrototypeMap, ArrayBuiltinsAssembler) {
  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  CodeStubArguments args(this, argc);
  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<Object> receiver = args.GetReceiver();
  TNode<Object> callbackfn = args.GetOptionalArgumentValue(0);
  TNode<Object> this_arg = args.GetOptionalArgumentValue(1);

  InitIteratingArrayBuiltinBody(context, receiver, callbackfn, this_arg, argc);

  GenerateIteratingTypedArrayBuiltinBody(
      "%TypedArray%.prototype.map",
      &ArrayBuiltinsAssembler::TypedArrayMapResultGenerator,
      &ArrayBuiltinsAssembler::TypedArrayMapProcessor);
}

class ArrayIncludesIndexofAssembler : public CodeStubAssembler {
 public:
  explicit ArrayIncludesIndexofAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  enum SearchVariant { kIncludes, kIndexOf };

  enum class SimpleElementKind { kSmiOrHole, kAny };

  void Generate(SearchVariant variant, TNode<IntPtrT> argc,
                TNode<Context> context);
  void GenerateSmiOrObject(SearchVariant variant, TNode<Context> context,
                           TNode<FixedArray> elements,
                           TNode<Object> search_element,
                           TNode<Smi> array_length, TNode<Smi> from_index,
                           SimpleElementKind array_kind);
  void GeneratePackedDoubles(SearchVariant variant,
                             TNode<FixedDoubleArray> elements,
                             TNode<Object> search_element,
                             TNode<Smi> array_length, TNode<Smi> from_index);
  void GenerateHoleyDoubles(SearchVariant variant,
                            TNode<FixedDoubleArray> elements,
                            TNode<Object> search_element,
                            TNode<Smi> array_length, TNode<Smi> from_index);

  void ReturnIfEmpty(TNode<Smi> length, TNode<Object> value) {
    Label done(this);
    GotoIf(SmiGreaterThan(length, SmiConstant(0)), &done);
    Return(value);
    BIND(&done);
  }

 private:
  // Use SIMD code for arrays larger than kSIMDThreshold (in builtins that have
  // SIMD implementations).
  const int kSIMDThreshold = 48;

  // For now, we can vectorize if:
  //   - SSE3/AVX are present (x86/x64). Note that if __AVX__ is defined, then
  //     __SSE3__ will be as well, so we just check __SSE3__.
  //   - Neon is present and the architecture is 64-bit (because Neon on 32-bit
  //     architecture lacks some instructions).
#if defined(__SSE3__) || defined(V8_HOST_ARCH_ARM64)
  const bool kCanVectorize = true;
#else
  const bool kCanVectorize = false;
#endif
};

void ArrayIncludesIndexofAssembler::Generate(SearchVariant variant,
                                             TNode<IntPtrT> argc,
                                             TNode<Context> context) {
  const int kSearchElementArg = 0;
  const int kFromIndexArg = 1;

  CodeStubArguments args(this, argc);

  TNode<Object> receiver = args.GetReceiver();
  TNode<Object> search_element =
      args.GetOptionalArgumentValue(kSearchElementArg);

  TNode<IntPtrT> intptr_zero = IntPtrConstant(0);

  Label init_index(this), return_not_found(this), call_runtime(this);

  // Take slow path if not a JSArray, if retrieving elements requires
  // traversing prototype, or if access checks are required.
  BranchIfFastJSArrayForRead(receiver, context, &init_index, &call_runtime);

  BIND(&init_index);
  TVARIABLE(IntPtrT, index_var, intptr_zero);
  TNode<JSArray> array = CAST(receiver);

  // JSArray length is always a positive Smi for fast arrays.
  CSA_DCHECK(this, TaggedIsPositiveSmi(LoadJSArrayLength(array)));
  TNode<Smi> array_length = LoadFastJSArrayLength(array);
  TNode<IntPtrT> array_length_untagged = PositiveSmiUntag(array_length);

  {
    // Initialize fromIndex.
    Label is_smi(this), is_nonsmi(this), done(this);

    // If no fromIndex was passed, default to 0.
    GotoIf(IntPtrLessThanOrEqual(args.GetLengthWithoutReceiver(),
                                 IntPtrConstant(kFromIndexArg)),
           &done);

    TNode<Object> start_from = args.AtIndex(kFromIndexArg);
    // Handle Smis and undefined here and everything else in runtime.
    // We must be very careful with side effects from the ToInteger conversion,
    // as the side effects might render previously checked assumptions about
    // the receiver being a fast JSArray and its length invalid.
    Branch(TaggedIsSmi(start_from), &is_smi, &is_nonsmi);

    BIND(&is_nonsmi);
    {
      GotoIfNot(IsUndefined(start_from), &call_runtime);
      Goto(&done);
    }
    BIND(&is_smi);
    {
      TNode<IntPtrT> intptr_start_from = SmiUntag(CAST(start_from));
      index_var = intptr_start_from;

      GotoIf(IntPtrGreaterThanOrEqual(index_var.value(), intptr_zero), &done);
      // The fromIndex is negative: add it to the array's length.
      index_var = IntPtrAdd(array_length_untagged, index_var.value());
      // Clamp negative results at zero.
      GotoIf(IntPtrGreaterThanOrEqual(index_var.value(), intptr_zero), &done);
      index_var = intptr_zero;
      Goto(&done);
    }
    BIND(&done);
  }

  // Fail early if startIndex >= array.length.
  GotoIf(IntPtrGreaterThanOrEqual(index_var.value(), array_length_untagged),
         &return_not_found);

  Label if_smi(this), if_smiorobjects(this), if_packed_doubles(this),
      if_holey_doubles(this);

  TNode<Int32T> elements_kind = LoadElementsKind(array);
  TNode<FixedArrayBase> elements = LoadElements(array);
  static_assert(PACKED_SMI_ELEMENTS == 0);
  static_assert(HOLEY_SMI_ELEMENTS == 1);
  static_assert(PACKED_ELEMENTS == 2);
  static_assert(HOLEY_ELEMENTS == 3);
  GotoIf(IsElementsKindLessThanOrEqual(elements_kind, HOLEY_SMI_ELEMENTS),
         &if_smi);
  GotoIf(IsElementsKindLessThanOrEqual(elements_kind, HOLEY_ELEMENTS),
         &if_smiorobjects);
  GotoIf(
      ElementsKindEqual(elements_kind, Int32Constant(PACKED_DOUBLE_ELEMENTS)),
      &if_packed_doubles);
  GotoIf(ElementsKindEqual(elements_kind, Int32Constant(HOLEY_DOUBLE_ELEMENTS)),
         &if_holey_doubles);
  GotoIf(IsElementsKindLessThanOrEqual(elements_kind,
                                       LAST_ANY_NONEXTENSIBLE_ELEMENTS_KIND),
         &if_smiorobjects);
  Goto(&return_not_found);

  BIND(&if_smi);
  {
    Builtin builtin = (variant == kIncludes) ? Builtin::kArrayIncludesSmi
                                             : Builtin::kArrayIndexOfSmi;
    TNode<Object> result =
        CallBuiltin(builtin, context, elements, search_element, array_length,
                    SmiTag(index_var.value()));
    args.PopAndReturn(result);
  }

  BIND(&if_smiorobjects);
  {
    Builtin builtin = (variant == kIncludes)
                          ? Builtin::kArrayIncludesSmiOrObject
                          : Builtin::kArrayIndexOfSmiOrObject;
    TNode<Object> result =
        CallBuiltin(builtin, context, elements, search_element, array_length,
                    SmiTag(index_var.value()));
    args.PopAndReturn(result);
  }

  BIND(&if_packed_doubles);
  {
    Builtin builtin = (variant == kIncludes)
                          ? Builtin::kArrayIncludesPackedDoubles
                          : Builtin::kArrayIndexOfPackedDoubles;
    TNode<Object> result =
        CallBuiltin(builtin, context, elements, search_element, array_length,
                    SmiTag(index_var.value()));
    args.PopAndReturn(result);
  }

  BIND(&if_holey_doubles);
  {
    Builtin builtin = (variant == kIncludes)
                          ? Builtin::kArrayIncludesHoleyDoubles
                          : Builtin::kArrayIndexOfHoleyDoubles;
    TNode<Object> result =
        CallBuiltin(builtin, context, elements, search_element, array_length,
                    SmiTag(index_var.value()));
    args.PopAndReturn(result);
  }

  BIND(&return_not_found);
  if (variant == kIncludes) {
    args.PopAndReturn(FalseConstant());
  } else {
    args.PopAndReturn(NumberConstant(-1));
  }

  BIND(&call_runtime);
  {
    TNode<Object> start_from = args.GetOptionalArgumentValue(kFromIndexArg);
    Runtime::FunctionId function = variant == kIncludes
                                       ? Runtime::kArrayIncludes_Slow
                                       : Runtime::kArrayIndexOf;
    args.PopAndReturn(
        CallRuntime(function, context, array, search_element, start_from));
  }
}

void ArrayIncludesIndexofAssembler::GenerateSmiOrObject(
    SearchVariant variant, TNode<Context> context, TNode<FixedArray> elements,
    TNode<Object> search_element, TNode<Smi> array_length,
    TNode<Smi> from_index, SimpleElementKind array_kind) {
  TVARIABLE(IntPtrT, index_var, SmiUntag(from_index));
  TVARIABLE(Float64T, search_num);
  TNode<IntPtrT> array_length_untagged = PositiveSmiUntag(array_length);

  Label ident_loop(this, &index_var), heap_num_loop(this, &search_num),
      string_loop(this), bigint_loop(this, &index_var),
      undef_loop(this, &index_var), not_smi(this), not_heap_num(this),
      return_found(this), return_not_found(this);

  GotoIfNot(TaggedIsSmi(search_element), &not_smi);
  search_num = SmiToFloat64(CAST(search_element));
  Goto(&heap_num_loop);

  BIND(&not_smi);
  if (variant == kIncludes) {
    GotoIf(IsUndefined(search_element), &undef_loop);
  }
  TNode<Map> map = LoadMap(CAST(search_element));
  GotoIfNot(IsHeapNumberMap(map), &not_heap_num);
  search_num = LoadHeapNumberValue(CAST(search_element));
  Goto(&heap_num_loop);

  BIND(&not_heap_num);
  TNode<Uint16T> search_type = LoadMapInstanceType(map);
  GotoIf(IsStringInstanceType(search_type), &string_loop);
  GotoIf(IsBigIntInstanceType(search_type), &bigint_loop);

  // Use UniqueInt32Constant instead of BoolConstant here in order to ensure
  // that the graph structure does not depend on the value of the predicate
  // (BoolConstant uses cached nodes).
  GotoIfNot(UniqueInt32Constant(kCanVectorize), &ident_loop);
  {
    Label simd_call(this);
    Branch(
        UintPtrLessThan(array_length_untagged, IntPtrConstant(kSIMDThreshold)),
        &ident_loop, &simd_call);
    BIND(&simd_call);
    TNode<ExternalReference> simd_function = ExternalConstant(
        ExternalReference::array_indexof_includes_smi_or_object());
    TNode<IntPtrT> result = UncheckedCast<IntPtrT>(CallCFunction(
        simd_function, MachineType::UintPtr(),
        std::make_pair(MachineType::TaggedPointer(), elements),
        std::make_pair(MachineType::UintPtr(), array_length_untagged),
        std::make_pair(MachineType::UintPtr(), index_var.value()),
        std::make_pair(MachineType::TaggedPointer(), search_element)));
    index_var = ReinterpretCast<IntPtrT>(result);
    Branch(IntPtrLessThan(index_var.value(), IntPtrConstant(0)),
           &return_not_found, &return_found);
  }

  BIND(&ident_loop);
  {
    GotoIfNot(UintPtrLessThan(index_var.value(), array_length_untagged),
              &ret
```