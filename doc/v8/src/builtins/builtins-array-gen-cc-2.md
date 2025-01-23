Response:
The user wants a summary of the functionality of the provided C++ code, which is part of the V8 JavaScript engine.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the file's purpose:** The file name `builtins-array-gen.cc` and the namespace `v8::internal` suggest this code implements built-in functions related to arrays in JavaScript. The `.cc` extension confirms it's C++ code. The user also provides a hint that if it ended with `.tq`, it would be Torque.

2. **Scan for key function names and keywords:** Look for function definitions (like `void ArrayBuiltinsAssembler::...`), macros like `TF_BUILTIN`, and relevant class names like `ArrayBuiltinsAssembler`, `SlowBoilerplateCloneAssembler`. Keywords like "constructor", "allocation", "clone", "elements", and "runtime" are important clues.

3. **Group related functionalities:**  Notice patterns in function names and code structure. For example, functions starting with `GenerateArray...Constructor` clearly deal with array creation. The `SlowBoilerplateCloneAssembler` class and its related builtins handle a different aspect: cloning array and object literals.

4. **Analyze the `ArrayBuiltinsAssembler` class:**
    * **Array Construction:** The code seems to have different ways to construct arrays depending on the number of arguments and whether allocation sites are being tracked. The `ArrayConstructorImpl`, `CreateArrayDispatchNoArgument`, `CreateArrayDispatchSingleArgument`, and `GenerateDispatchToArrayStub` functions are central to this.
    * **Handling different element kinds:** The code iterates through different `ElementsKind` (like `PACKED_SMI_ELEMENTS`, `HOLEY_ELEMENTS`) indicating that V8 optimizes array storage based on the type of elements.
    * **Allocation Sites:**  The code frequently mentions `AllocationSite`. This is a V8 mechanism for optimization, allowing the engine to track how objects are allocated.
    * **Runtime Calls:**  Functions like `TailCallRuntime` and `CallRuntime` indicate that some operations are delegated to the more general V8 runtime.

5. **Analyze the `SlowBoilerplateCloneAssembler` class:**
    * **Boilerplates:**  The term "boilerplate" suggests this code deals with optimizing the creation of objects and arrays that have a predefined structure (like literals).
    * **Cloning:** The class name and functions like `CloneIfObjectOrArray`, `CloneElementsOfFixedArray` strongly indicate this part handles efficiently copying or "cloning" these boilerplates.
    * **Nested Objects/Arrays:** The code handles cases where arrays or objects contain other arrays or objects, suggesting a deep cloning mechanism.
    * **Performance Optimization:** The comments mention avoiding full runtime calls for faster creation in common cases.

6. **Connect to JavaScript:** Think about how these C++ functions relate to JavaScript syntax and behavior. The `Array()` constructor in JavaScript is the obvious connection to the array construction functions. Array and object literals (e.g., `[]`, `{}`) relate to the boilerplate cloning logic.

7. **Construct Examples:** Create simple JavaScript examples that illustrate the functionalities observed in the C++ code. `new Array()` with different argument counts, and array/object literals are good starting points.

8. **Identify Potential Errors:** Consider what mistakes JavaScript developers might make that these built-ins would encounter. Creating arrays with very large sizes or unexpected element types are possibilities.

9. **Address the ".tq" detail:**  Acknowledge the user's point about `.tq` indicating Torque and explain the difference between Torque and C++ within V8.

10. **Summarize and Organize:**  Combine the findings into a clear and concise summary, grouping related functionalities and using appropriate technical terms. Structure the summary to cover the different aspects identified (array construction, boilerplate cloning).

11. **Review and Refine:**  Read through the summary to ensure accuracy, clarity, and completeness. Check if all parts of the user's request have been addressed. For example, make sure the assumptions, inputs, and outputs for code logic are clearly stated.

**(Self-Correction Example during the process):**  Initially, I might focus heavily on the different `ElementsKind` and try to explain each one in detail. However, realizing the user wants a *functional* summary, it's more important to highlight *why* these different kinds exist (optimization) rather than going into the specifics of each. Also, I need to ensure the connection to Javascript is explicit.
```cpp
void ArrayBuiltinsAssembler::GenerateDispatchToConstructor(
    TNode<Context> context, TNode<JSFunction> target, TNode<Object> new_target,
    TNode<Int32T> argc, std::optional<TNode<AllocationSite>> maybe_allocation_site,
    AllocationSiteOverrideMode mode) {
  Label fast_elements(this), normal_sequence(this);
  TVARIABLE(AllocationSite, var_allocation_site);
  if (maybe_allocation_site.has_value()) {
    var_allocation_site = maybe_allocation_site.value();
    Goto(&fast_elements);
  } else {
    Goto(&normal_sequence);
  }

  BIND(&fast_elements);
  {
    TNode<AllocationSite> allocation_site = var_allocation_site.value();
    TNode<Smi> transition_info_or_boilerplate = LoadObjectField<Smi>(
        allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset);
    // If we have a proper AllocationSite, try the fast path for constructing
    // empty arrays.
    TNode<Word32T> fast_elements_kind_mask = LoadObjectField<Word32T>(
        allocation_site, AllocationSite::kFastElementsKindMaskOffset);
    TNode<Int32T> allocation_memento_elements_kind =
        DecodeWord32<ElementsKindField>(fast_elements_kind_mask);
    TVARIABLE(Int32T, var_elements_kind, allocation_memento_elements_kind);

    // If the allocation site tracks only one specific kind, then we can
    // immediately jump to the fast path.
    Label call_normal_constructor(this);
    GotoIf(Word32NotEqual(fast_elements_kind_mask,
                          Int32Constant(kFastElementsKindSingleMask)),
           &call_normal_constructor);

    // The AllocationSite is guaranteed to have valid transition info.
    GotoIf(SmiEqual(transition_info_or_boilerplate, SmiConstant(0)),
           &call_normal_constructor);

    // Fall back to the normal constructor if the array is not empty.
    // TODO(v8:11788): It might be worth generating a more specialized code for
    // this case.
    GotoIf(SmiNotEqual(argc, SmiConstant(0)), &call_normal_constructor);
    {
      ElementsKind kind = static_cast<ElementsKind>(
          allocation_memento_elements_kind.value());
      Callable callable =
          CodeFactory::ArrayNoArgumentConstructor(isolate(), kind, mode);
      TailCallArrayConstructorStub(callable, context, target, allocation_site,
                                   argc);
    }

    BIND(&call_normal_constructor);
    // The allocation site tracks multiple kinds of elements. We need to check
    // the actual requested elements kind.
    // Check if the {new.target} is the original Array function. If it isn't,
    // then we might be dealing with a subclass, so we can't perform the
    // elements kind check.
    GotoIf(TaggedNotEqual(target, new_target), &normal_sequence);

    // If the feedback vector indicates that we should allocate a HOLEY
    // element backing store, then we can skip the checks for PACKED elements
    // and go directly to the HOLEY case.
    TNode<Smi> fast_elements_kind_holey_mask = LoadObjectField<Smi>(
        allocation_site, AllocationSite::kFastElementsKindHoleyMaskOffset);
    Label holey_sequence(this);
    GotoIf(SmiEqual(fast_elements_kind_holey_mask, SmiConstant(0)),
           &holey_sequence);
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(kHoleyDoubleElements)));
      var_elements_kind = Int32Constant(HOLEY_DOUBLE_ELEMENTS);
      Goto(&normal_sequence);
    }
    BIND(&holey_sequence);
    GotoIf(SmiEqual(fast_elements_kind_holey_mask,
                   SmiConstant(kHoleySmiOrObjectElements)),
           &normal_sequence);
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate, SmiConstant(HOLEY_ELEMENTS)));
      var_elements_kind = Int32Constant(HOLEY_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate, SmiConstant(PACKED_DOUBLE_ELEMENTS)));
      var_elements_kind = Int32Constant(PACKED_DOUBLE_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate, SmiConstant(PACKED_ELEMENTS)));
      var_elements_kind = Int32Constant(PACKED_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate, SmiConstant(PACKED_SMI_ELEMENTS)));
      var_elements_kind = Int32Constant(PACKED_SMI_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(FAST_HOLEY_DOUBLE_ELEMENTS)));
      var_elements_kind = Int32Constant(HOLEY_DOUBLE_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(FAST_HOLEY_ELEMENTS)));
      var_elements_kind = Int32Constant(HOLEY_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(FAST_PACKED_DOUBLE_ELEMENTS)));
      var_elements_kind = Int32Constant(PACKED_DOUBLE_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(FAST_PACKED_ELEMENTS)));
      var_elements_kind = Int32Constant(PACKED_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(FAST_PACKED_SMI_ELEMENTS)));
      var_elements_kind = Int32Constant(PACKED_SMI_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(FAST_HOLEY_SMI_ELEMENTS)));
      var_elements_kind = Int32Constant(HOLEY_SMI_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(TERMINAL_FAST_DOUBLE_ELEMENTS)));
      var_elements_kind = Int32Constant(HOLEY_DOUBLE_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(TERMINAL_FAST_ELEMENTS)));
      var_elements_kind = Int32Constant(HOLEY_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(FAST_HOLEY_DOUBLE_ELEMENTS)));
      var_elements_kind = Int32Constant(HOLEY_DOUBLE_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(FAST_HOLEY_ELEMENTS)));
      var_elements_kind = Int32Constant(HOLEY_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(FAST_PACKED_DOUBLE_ELEMENTS)));
      var_elements_kind = Int32Constant(PACKED_DOUBLE_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(FAST_PACKED_ELEMENTS)));
      var_elements_kind = Int32Constant(PACKED_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(FAST_PACKED_SMI_ELEMENTS)));
      var_elements_kind = Int32Constant(PACKED_SMI_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(FAST_HOLEY_SMI_ELEMENTS)));
      var_elements_kind = Int32Constant(HOLEY_SMI_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(TERMINAL_FAST_DOUBLE_ELEMENTS)));
      var_elements_kind = Int32Constant(HOLEY_DOUBLE_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate,
                SmiConstant(TERMINAL_FAST_ELEMENTS)));
      var_elements_kind = Int32Constant(HOLEY_ELEMENTS);
      Goto(&normal_sequence);
    }
    {
      StoreSmiObjectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info_or_boilerplate, SmiConstant(fast_elements_kind_holey_mask)));
      Goto(&normal_sequence);
    }
    BIND(&normal_sequence);

    // TODO(ishell): Compute the builtin index dynamically instead of
    // iterating over all expected elements kinds.
    // TODO(ishell): Given that the code above ensures that the elements kind
    // is holey we can skip checking with non-holey elements kinds.
    int last_index =
        GetSequenceIndexFromFastElementsKind(TERMINAL_FAST_ELEMENTS_KIND);
    for (int i = 0; i <= last_index; ++i) {
      Label next(this);
      ElementsKind kind = GetFastElementsKindFromSequenceIndex(i);
      GotoIfNot(Word32Equal(var_elements_kind.value(), Int32Constant(kind)),
                &next);

      Callable callable =
          CodeFactory::ArraySingleArgumentConstructor(isolate(), kind, mode);

      TailCallArrayConstructorStub(callable, context, target, *allocation_site,
                                   argc);

      BIND(&next);
    }

    // If we reached this point there is a problem.
    Abort(AbortReason::kUnexpectedElementsKindInArrayConstructor);
  }
}

void ArrayBuiltinsAssembler::GenerateDispatchToArrayStub(
    TNode<Context> context, TNode<JSFunction> target, TNode<Int32T> argc,
    AllocationSiteOverrideMode mode,
    std::optional<TNode<AllocationSite>> allocation_site) {
  CodeStubArguments args(this, argc);
  Label check_one_case(this), fallthrough(this);
  GotoIfNot(IntPtrEqual(args.GetLengthWithoutReceiver(), IntPtrConstant(0)),
            &check_one_case);
  CreateArrayDispatchNoArgument(context, target, argc, mode, allocation_site);

  BIND(&check_one_case);
  GotoIfNot(IntPtrEqual(args.GetLengthWithoutReceiver(), IntPtrConstant(1)),
            &fallthrough);
  CreateArrayDispatchSingleArgument(context, target, argc, mode,
                                    allocation_site);

  BIND(&fallthrough);
}

TF_BUILTIN(ArrayConstructorImpl, ArrayBuiltinsAssembler) {
  auto target = Parameter<JSFunction>(Descriptor::kTarget);
  auto new_target = Parameter<Object>(Descriptor::kNewTarget);
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
  auto maybe_allocation_site =
      Parameter<HeapObject>(Descriptor::kAllocationSite);

  // Initial map for the builtin Array functions should be Map.
  CSA_DCHECK(this, IsMap(CAST(LoadObjectField(
                       target, JSFunction::kPrototypeOrInitialMapOffset))));

  // We should either have undefined or a valid AllocationSite
  CSA_DCHECK(this, Word32Or(IsUndefined(maybe_allocation_site),
                            IsAllocationSite(maybe_allocation_site)));

  // "Enter" the context of the Array function.
  TNode<Context> context =
      CAST(LoadObjectField(target, JSFunction::kContextOffset));

  Label runtime(this, Label::kDeferred);
  GotoIf(TaggedNotEqual(target, new_target), &runtime);

  Label no_info(this);
  // If the feedback vector is the undefined value call an array constructor
  // that doesn't use AllocationSites.
  GotoIf(IsUndefined(maybe_allocation_site), &no_info);

  GenerateDispatchToArrayStub(context, target, argc, DONT_OVERRIDE,
                              CAST(maybe_allocation_site));
  Goto(&runtime);

  BIND(&no_info);
  GenerateDispatchToArrayStub(context, target, argc, DISABLE_ALLOCATION_SITES);
  Goto(&runtime);

  BIND(&runtime);
  GenerateArrayNArgumentsConstructor(context, target, new_target, argc,
                                     maybe_allocation_site);
}

void ArrayBuiltinsAssembler::GenerateConstructor(
    TNode<Context> context, TNode<HeapObject> array_function,
    TNode<Map> array_map, TNode<Object> array_size,
    TNode<HeapObject> allocation_site, ElementsKind elements_kind,
    AllocationSiteMode mode) {
  Label ok(this);
  Label smi_size(this);
  Label small_smi_size(this);
  Label call_runtime(this, Label::kDeferred);

  Branch(TaggedIsSmi(array_size), &smi_size, &call_runtime);

  BIND(&smi_size);
  {
    TNode<Smi> array_size_smi = CAST(array_size);

    if (IsFastPackedElementsKind(elements_kind)) {
      Label abort(this, Label::kDeferred);
      Branch(SmiEqual(array_size_smi, SmiConstant(0)), &small_smi_size, &abort);

      BIND(&abort);
      TNode<Smi> reason =
          SmiConstant(AbortReason::kAllocatingNonEmptyPackedArray);
      TailCallRuntime(Runtime::kAbort, context, reason);
    } else {
      Branch(SmiAboveOrEqual(array_size_smi,
                             SmiConstant(JSArray::kInitialMaxFastElementArray)),
             &call_runtime, &small_smi_size);
    }

    BIND(&small_smi_size);
    {
      TNode<JSArray> array = AllocateJSArray(
          elements_kind, array_map, array_size_smi, array_size_smi,
          mode == DONT_TRACK_ALLOCATION_SITE
              ? std::optional<TNode<AllocationSite>>(std::nullopt)
              : CAST(allocation_site));
      Return(array);
    }
  }

  BIND(&call_runtime);
  {
    TailCallRuntimeNewArray(context, array_function, array_size, array_function,
                            allocation_site);
  }
}

void ArrayBuiltinsAssembler::GenerateArrayNoArgumentConstructor(
    ElementsKind kind, AllocationSiteOverrideMode mode) {
  using Descriptor = ArrayNoArgumentConstructorDescriptor;
  TNode<NativeContext> native_context = LoadObjectField<NativeContext>(
      Parameter<HeapObject>(Descriptor::kFunction), JSFunction::kContextOffset);
  bool track_allocation_site =
      AllocationSite::ShouldTrack(kind) && mode != DISABLE_ALLOCATION_SITES;
  std::optional<TNode<AllocationSite>> allocation_site =
      track_allocation_site
          ? Parameter<AllocationSite>(Descriptor::kAllocationSite)
          : std::optional<TNode<AllocationSite>>(std::nullopt);
  TNode<Map> array_map = LoadJSArrayElementsMap(kind, native_context);
  TNode<JSArray> array = AllocateJSArray(
      kind, array_map, IntPtrConstant(JSArray::kPreallocatedArrayElements),
      SmiConstant(0), allocation_site);
  Return(array);
}

void ArrayBuiltinsAssembler::GenerateArraySingleArgumentConstructor(
    ElementsKind kind, AllocationSiteOverrideMode mode) {
  using Descriptor = ArraySingleArgumentConstructorDescriptor;
  auto context = Parameter<Context>(Descriptor::kContext);
  auto function = Parameter<HeapObject>(Descriptor::kFunction);
  TNode<NativeContext> native_context =
      CAST(LoadObjectField(function, JSFunction::kContextOffset));
  TNode<Map> array_map = LoadJSArrayElementsMap(kind, native_context);

  AllocationSiteMode allocation_site_mode = DONT_TRACK_ALLOCATION_SITE;
  if (mode == DONT_OVERRIDE) {
    allocation_site_mode = AllocationSite::ShouldTrack(kind)
                               ? TRACK_ALLOCATION_SITE
                               : DONT_TRACK_ALLOCATION_SITE;
  }

  auto array_size = Parameter<Object>(Descriptor::kArraySizeSmiParameter);
  // allocation_site can be Undefined or an AllocationSite
  auto allocation_site = Parameter<HeapObject>(Descriptor::kAllocationSite);

  GenerateConstructor(context, function, array_map, array_size, allocation_site,
                      kind, allocation_site_mode);
}

void ArrayBuiltinsAssembler::GenerateArrayNArgumentsConstructor(
    TNode<Context> context, TNode<JSFunction> target, TNode<Object> new_target,
    TNode<Int32T> argc, TNode<HeapObject> maybe_allocation_site) {
  // Replace incoming JS receiver argument with the target.
  // TODO(ishell): Avoid replacing the target on the stack and just add it
  // as another additional parameter for Runtime::kNewArray.
  CodeStubArguments args(this, argc);
  args.SetReceiver(target);

  // Adjust arguments count for the runtime call:
  // +2 for new_target and maybe_allocation_site.
  argc = Int32Add(TruncateIntPtrToInt32(args.GetLengthWithReceiver()),
                  Int32Constant(2));
  TailCallRuntime(Runtime::kNewArray, argc, context, new_target,
                  maybe_allocation_site);
}

TF_BUILTIN(ArrayNArgumentsConstructor, ArrayBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto target = Parameter<JSFunction>(Descriptor::kFunction);
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
  auto maybe_allocation_site =
      Parameter<HeapObject>(Descriptor::kAllocationSite);

  GenerateArrayNArgumentsConstructor(context, target, target, argc,
                                     maybe_allocation_site);
}

#define GENERATE_ARRAY_CTOR(name, kind_camel, kind_caps, mode_camel, \
                            mode_caps)                               \
  TF_BUILTIN(Array##name##Constructor_##kind_camel##_##mode_camel,   \
             ArrayBuiltinsAssembler) {                               \
    GenerateArray##name##Constructor(kind_caps, mode_caps);          \
  }

// The ArrayNoArgumentConstructor builtin family.
GENERATE_ARRAY_CTOR(NoArgument, PackedSmi, PACKED_SMI_ELEMENTS, DontOverride,
                    DONT_OVERRIDE)
GENERATE_ARRAY_CTOR(NoArgument, HoleySmi, HOLEY_SMI_ELEMENTS, DontOverride,
                    DONT_OVERRIDE)
GENERATE_ARRAY_CTOR(NoArgument, PackedSmi, PACKED_SMI_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(NoArgument, HoleySmi, HOLEY_SMI_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(NoArgument, Packed, PACKED_ELEMENTS, DisableAllocationSites,
                    DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(NoArgument, Holey, HOLEY_ELEMENTS, DisableAllocationSites,
                    DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(NoArgument, PackedDouble, PACKED_DOUBLE_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(NoArgument, HoleyDouble, HOLEY_DOUBLE_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)

// The ArraySingleArgumentConstructor builtin family.
GENERATE_ARRAY_CTOR(SingleArgument, PackedSmi, PACKED_SMI_ELEMENTS,
                    DontOverride, DONT_OVERRIDE)
GENERATE_ARRAY_CTOR(SingleArgument, HoleySmi, HOLEY_SMI_ELEMENTS, DontOverride,
                    DONT_OVERRIDE)
GENERATE_ARRAY_CTOR(SingleArgument, PackedSmi, PACKED_SMI_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(SingleArgument, HoleySmi, HOLEY_SMI_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(SingleArgument, Packed, PACKED_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(SingleArgument, Holey, HOLEY_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(SingleArgument, PackedDouble, PACKED_DOUBLE_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(SingleArgument, HoleyDouble, HOLEY_DOUBLE_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)

#undef GENERATE_ARRAY_CTOR

class SlowBoilerplateCloneAssembler : public CodeStubAssembler {
 public:
  explicit SlowBoilerplateCloneAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  // If `item` is an object or an array, deep-clone it and jump to `cloned`.
  void CloneIfObjectOrArray(TNode<Object> item, TVariable<Object>& clone,
                            TVariable<Object>& current_allocation_site,
                            TNode<Context> context, Label* cloned,
                            Label* not_cloned, Label* bailout) {
    Label is_object(this, &current_allocation_site),
        is_array(this, &current_allocation_site);

    GotoIf(TaggedIsSmi(item), not_cloned);
    GotoIf(IsJSArray(CAST(item)), &is_array);
    GotoIf(IsJSObject(CAST(item)), &is_object);
    Goto(not_cloned);

    BIND(&is_array);
    {
      // Consume the next AllocationSite. All objects inside this array, as well
      // as all sibling objects (until a new array is encountered) will use this
      // AllocationSite. E.g., in [1, 2, {a: 3}, [4, 5], {b: 6}], the object {a:
      // 3} uses the topmost AllocationSite, and the object {b: 6} uses the
      // AllocationSite of [4, 5].
      if (V8_ALLOCATION_SITE_TRACKING_BOOL) {
        current_allocation_site =
            LoadNestedAllocationSite(CAST(current_allocation_site.value()));

        // Ensure we're consuming the AllocationSites in the correct order.
        CSA_DCHECK(
            this,
            TaggedEqual(LoadBoilerplate(CAST(current_allocation_site.value())),
                        item));
      }

      auto clone_and_next_allocation_site = CallBuiltin<PairT<Object, Object>>(
          Builtin::kCreateArrayFromSlowBoilerplateHelper, context,
          current_allocation_site.value(), item);

      clone = Projection<0>(clone_and_next_allocation_site);
      GotoIf(IsUndefined(clone.value()), bailout);
      current_allocation_site = Projection<1>(clone_and_next_allocation_site);
      Goto(cloned);
    }

    BIND(&is_object);
    {
      auto clone_and_next_allocation_site = CallBuiltin<PairT<Object, Object>>(
          Builtin::kCreateObjectFromSlowBoilerplateHelper, context,
          current_allocation_site.value(), item);
      clone = Projection<0>(clone_and_next_allocation_site);
      GotoIf(IsUndefined(clone.value()), bailout);
      current_allocation_site = Projection<1>(clone_and_next_allocation_site);
      Goto(cloned);
    }
  }

  void CloneElementsOfFixedArray(TNode<FixedArrayBase> elements,
                                 TNode<Smi> length, TNode<Int32T> elements_kind,
                                 TVariable<Object>& current_allocation_site,
                                 TNode<Context> context, Label* done,
                                 Label* bailout) {
    CSA_DCHECK(this, SmiNotEqual(length, SmiConstant(0)));

    auto loop_body = [&](TNode<IntPtrT> index) {
      TVARIABLE(Object, clone);
      Label cloned(this, &clone),
          done_with_element(this, &current_allocation_site);

      TNode<Object> element = LoadFixedArrayElement(CAST(elements), index);
      CloneIfObjectOrArray(element, clone, current_allocation_site, context,
                           &cloned, &done_with_element, bailout);

      BIND(&cloned);
      {
        StoreFixedArrayElement(CAST(elements), index, clone.value());
        Goto(&done_with_element);
      }

      BIND(&done_with_element);
    };
    VariableList loop_vars({&current_allocation_site}, zone());
    BuildFastLoop<IntPtrT>(loop_vars, IntPtrConstant(0),
                           PositiveSmiUntag(length), loop_body, 1,
                           LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);
    Goto(done);
  }
};

TF_BUILTIN(CreateArrayFromSlowBoilerplate, SlowBoilerplateCloneAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto feedback_vector = Parameter<FeedbackVector>(Descriptor::kFeedbackVector);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);

  Label call_runtime(this);

  TNode<Object> maybe_allocation_site =
      CAST(LoadFeedbackVectorSlot(feedback_vector, slot));
  GotoIfNot(HasBoilerplate(maybe_allocation_site), &call_runtime);

  TNode<AllocationSite> allocation_site = CAST(maybe_allocation_site);
  TNode<JSArray> boilerplate = CAST(LoadBoilerplate(allocation_site));

  {
    auto clone_and_next_allocation_site = CallBuiltin<PairT<Object, Object>>(
        Builtin::kCreateArrayFromSlowBoilerplateHelper, context,
        allocation_site, boilerplate);
    TNode<Object> result = Projection<0>(clone_and_next_allocation_site);

    GotoIf(IsUndefined(result), &call_runtime);
    Return(result);
  }

  BIND(&call_runtime);
  {
    auto boilerplate_descriptor = Parameter<ArrayBo
### 提示词
```
这是目录为v8/src/builtins/builtins-array-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-array-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
jectFieldNoWriteBarrier(
          *allocation_site, AllocationSite::kTransitionInfoOrBoilerplateOffset,
          SmiOr(transition_info, SmiConstant(fast_elements_kind_holey_mask)));
      Goto(&normal_sequence);
    }
    BIND(&normal_sequence);

    // TODO(ishell): Compute the builtin index dynamically instead of
    // iterating over all expected elements kinds.
    // TODO(ishell): Given that the code above ensures that the elements kind
    // is holey we can skip checking with non-holey elements kinds.
    int last_index =
        GetSequenceIndexFromFastElementsKind(TERMINAL_FAST_ELEMENTS_KIND);
    for (int i = 0; i <= last_index; ++i) {
      Label next(this);
      ElementsKind kind = GetFastElementsKindFromSequenceIndex(i);
      GotoIfNot(Word32Equal(var_elements_kind.value(), Int32Constant(kind)),
                &next);

      Callable callable =
          CodeFactory::ArraySingleArgumentConstructor(isolate(), kind, mode);

      TailCallArrayConstructorStub(callable, context, target, *allocation_site,
                                   argc);

      BIND(&next);
    }

    // If we reached this point there is a problem.
    Abort(AbortReason::kUnexpectedElementsKindInArrayConstructor);
  }
}

void ArrayBuiltinsAssembler::GenerateDispatchToArrayStub(
    TNode<Context> context, TNode<JSFunction> target, TNode<Int32T> argc,
    AllocationSiteOverrideMode mode,
    std::optional<TNode<AllocationSite>> allocation_site) {
  CodeStubArguments args(this, argc);
  Label check_one_case(this), fallthrough(this);
  GotoIfNot(IntPtrEqual(args.GetLengthWithoutReceiver(), IntPtrConstant(0)),
            &check_one_case);
  CreateArrayDispatchNoArgument(context, target, argc, mode, allocation_site);

  BIND(&check_one_case);
  GotoIfNot(IntPtrEqual(args.GetLengthWithoutReceiver(), IntPtrConstant(1)),
            &fallthrough);
  CreateArrayDispatchSingleArgument(context, target, argc, mode,
                                    allocation_site);

  BIND(&fallthrough);
}

TF_BUILTIN(ArrayConstructorImpl, ArrayBuiltinsAssembler) {
  auto target = Parameter<JSFunction>(Descriptor::kTarget);
  auto new_target = Parameter<Object>(Descriptor::kNewTarget);
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
  auto maybe_allocation_site =
      Parameter<HeapObject>(Descriptor::kAllocationSite);

  // Initial map for the builtin Array functions should be Map.
  CSA_DCHECK(this, IsMap(CAST(LoadObjectField(
                       target, JSFunction::kPrototypeOrInitialMapOffset))));

  // We should either have undefined or a valid AllocationSite
  CSA_DCHECK(this, Word32Or(IsUndefined(maybe_allocation_site),
                            IsAllocationSite(maybe_allocation_site)));

  // "Enter" the context of the Array function.
  TNode<Context> context =
      CAST(LoadObjectField(target, JSFunction::kContextOffset));

  Label runtime(this, Label::kDeferred);
  GotoIf(TaggedNotEqual(target, new_target), &runtime);

  Label no_info(this);
  // If the feedback vector is the undefined value call an array constructor
  // that doesn't use AllocationSites.
  GotoIf(IsUndefined(maybe_allocation_site), &no_info);

  GenerateDispatchToArrayStub(context, target, argc, DONT_OVERRIDE,
                              CAST(maybe_allocation_site));
  Goto(&runtime);

  BIND(&no_info);
  GenerateDispatchToArrayStub(context, target, argc, DISABLE_ALLOCATION_SITES);
  Goto(&runtime);

  BIND(&runtime);
  GenerateArrayNArgumentsConstructor(context, target, new_target, argc,
                                     maybe_allocation_site);
}

void ArrayBuiltinsAssembler::GenerateConstructor(
    TNode<Context> context, TNode<HeapObject> array_function,
    TNode<Map> array_map, TNode<Object> array_size,
    TNode<HeapObject> allocation_site, ElementsKind elements_kind,
    AllocationSiteMode mode) {
  Label ok(this);
  Label smi_size(this);
  Label small_smi_size(this);
  Label call_runtime(this, Label::kDeferred);

  Branch(TaggedIsSmi(array_size), &smi_size, &call_runtime);

  BIND(&smi_size);
  {
    TNode<Smi> array_size_smi = CAST(array_size);

    if (IsFastPackedElementsKind(elements_kind)) {
      Label abort(this, Label::kDeferred);
      Branch(SmiEqual(array_size_smi, SmiConstant(0)), &small_smi_size, &abort);

      BIND(&abort);
      TNode<Smi> reason =
          SmiConstant(AbortReason::kAllocatingNonEmptyPackedArray);
      TailCallRuntime(Runtime::kAbort, context, reason);
    } else {
      Branch(SmiAboveOrEqual(array_size_smi,
                             SmiConstant(JSArray::kInitialMaxFastElementArray)),
             &call_runtime, &small_smi_size);
    }

    BIND(&small_smi_size);
    {
      TNode<JSArray> array = AllocateJSArray(
          elements_kind, array_map, array_size_smi, array_size_smi,
          mode == DONT_TRACK_ALLOCATION_SITE
              ? std::optional<TNode<AllocationSite>>(std::nullopt)
              : CAST(allocation_site));
      Return(array);
    }
  }

  BIND(&call_runtime);
  {
    TailCallRuntimeNewArray(context, array_function, array_size, array_function,
                            allocation_site);
  }
}

void ArrayBuiltinsAssembler::GenerateArrayNoArgumentConstructor(
    ElementsKind kind, AllocationSiteOverrideMode mode) {
  using Descriptor = ArrayNoArgumentConstructorDescriptor;
  TNode<NativeContext> native_context = LoadObjectField<NativeContext>(
      Parameter<HeapObject>(Descriptor::kFunction), JSFunction::kContextOffset);
  bool track_allocation_site =
      AllocationSite::ShouldTrack(kind) && mode != DISABLE_ALLOCATION_SITES;
  std::optional<TNode<AllocationSite>> allocation_site =
      track_allocation_site
          ? Parameter<AllocationSite>(Descriptor::kAllocationSite)
          : std::optional<TNode<AllocationSite>>(std::nullopt);
  TNode<Map> array_map = LoadJSArrayElementsMap(kind, native_context);
  TNode<JSArray> array = AllocateJSArray(
      kind, array_map, IntPtrConstant(JSArray::kPreallocatedArrayElements),
      SmiConstant(0), allocation_site);
  Return(array);
}

void ArrayBuiltinsAssembler::GenerateArraySingleArgumentConstructor(
    ElementsKind kind, AllocationSiteOverrideMode mode) {
  using Descriptor = ArraySingleArgumentConstructorDescriptor;
  auto context = Parameter<Context>(Descriptor::kContext);
  auto function = Parameter<HeapObject>(Descriptor::kFunction);
  TNode<NativeContext> native_context =
      CAST(LoadObjectField(function, JSFunction::kContextOffset));
  TNode<Map> array_map = LoadJSArrayElementsMap(kind, native_context);

  AllocationSiteMode allocation_site_mode = DONT_TRACK_ALLOCATION_SITE;
  if (mode == DONT_OVERRIDE) {
    allocation_site_mode = AllocationSite::ShouldTrack(kind)
                               ? TRACK_ALLOCATION_SITE
                               : DONT_TRACK_ALLOCATION_SITE;
  }

  auto array_size = Parameter<Object>(Descriptor::kArraySizeSmiParameter);
  // allocation_site can be Undefined or an AllocationSite
  auto allocation_site = Parameter<HeapObject>(Descriptor::kAllocationSite);

  GenerateConstructor(context, function, array_map, array_size, allocation_site,
                      kind, allocation_site_mode);
}

void ArrayBuiltinsAssembler::GenerateArrayNArgumentsConstructor(
    TNode<Context> context, TNode<JSFunction> target, TNode<Object> new_target,
    TNode<Int32T> argc, TNode<HeapObject> maybe_allocation_site) {
  // Replace incoming JS receiver argument with the target.
  // TODO(ishell): Avoid replacing the target on the stack and just add it
  // as another additional parameter for Runtime::kNewArray.
  CodeStubArguments args(this, argc);
  args.SetReceiver(target);

  // Adjust arguments count for the runtime call:
  // +2 for new_target and maybe_allocation_site.
  argc = Int32Add(TruncateIntPtrToInt32(args.GetLengthWithReceiver()),
                  Int32Constant(2));
  TailCallRuntime(Runtime::kNewArray, argc, context, new_target,
                  maybe_allocation_site);
}

TF_BUILTIN(ArrayNArgumentsConstructor, ArrayBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto target = Parameter<JSFunction>(Descriptor::kFunction);
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
  auto maybe_allocation_site =
      Parameter<HeapObject>(Descriptor::kAllocationSite);

  GenerateArrayNArgumentsConstructor(context, target, target, argc,
                                     maybe_allocation_site);
}

#define GENERATE_ARRAY_CTOR(name, kind_camel, kind_caps, mode_camel, \
                            mode_caps)                               \
  TF_BUILTIN(Array##name##Constructor_##kind_camel##_##mode_camel,   \
             ArrayBuiltinsAssembler) {                               \
    GenerateArray##name##Constructor(kind_caps, mode_caps);          \
  }

// The ArrayNoArgumentConstructor builtin family.
GENERATE_ARRAY_CTOR(NoArgument, PackedSmi, PACKED_SMI_ELEMENTS, DontOverride,
                    DONT_OVERRIDE)
GENERATE_ARRAY_CTOR(NoArgument, HoleySmi, HOLEY_SMI_ELEMENTS, DontOverride,
                    DONT_OVERRIDE)
GENERATE_ARRAY_CTOR(NoArgument, PackedSmi, PACKED_SMI_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(NoArgument, HoleySmi, HOLEY_SMI_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(NoArgument, Packed, PACKED_ELEMENTS, DisableAllocationSites,
                    DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(NoArgument, Holey, HOLEY_ELEMENTS, DisableAllocationSites,
                    DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(NoArgument, PackedDouble, PACKED_DOUBLE_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(NoArgument, HoleyDouble, HOLEY_DOUBLE_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)

// The ArraySingleArgumentConstructor builtin family.
GENERATE_ARRAY_CTOR(SingleArgument, PackedSmi, PACKED_SMI_ELEMENTS,
                    DontOverride, DONT_OVERRIDE)
GENERATE_ARRAY_CTOR(SingleArgument, HoleySmi, HOLEY_SMI_ELEMENTS, DontOverride,
                    DONT_OVERRIDE)
GENERATE_ARRAY_CTOR(SingleArgument, PackedSmi, PACKED_SMI_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(SingleArgument, HoleySmi, HOLEY_SMI_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(SingleArgument, Packed, PACKED_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(SingleArgument, Holey, HOLEY_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(SingleArgument, PackedDouble, PACKED_DOUBLE_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)
GENERATE_ARRAY_CTOR(SingleArgument, HoleyDouble, HOLEY_DOUBLE_ELEMENTS,
                    DisableAllocationSites, DISABLE_ALLOCATION_SITES)

#undef GENERATE_ARRAY_CTOR

class SlowBoilerplateCloneAssembler : public CodeStubAssembler {
 public:
  explicit SlowBoilerplateCloneAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  // If `item` is an object or an array, deep-clone it and jump to `cloned`.
  void CloneIfObjectOrArray(TNode<Object> item, TVariable<Object>& clone,
                            TVariable<Object>& current_allocation_site,
                            TNode<Context> context, Label* cloned,
                            Label* not_cloned, Label* bailout) {
    Label is_object(this, &current_allocation_site),
        is_array(this, &current_allocation_site);

    GotoIf(TaggedIsSmi(item), not_cloned);
    GotoIf(IsJSArray(CAST(item)), &is_array);
    GotoIf(IsJSObject(CAST(item)), &is_object);
    Goto(not_cloned);

    BIND(&is_array);
    {
      // Consume the next AllocationSite. All objects inside this array, as well
      // as all sibling objects (until a new array is encountered) will use this
      // AllocationSite. E.g., in [1, 2, {a: 3}, [4, 5], {b: 6}], the object {a:
      // 3} uses the topmost AllocationSite, and the object {b: 6} uses the
      // AllocationSite of [4, 5].
      if (V8_ALLOCATION_SITE_TRACKING_BOOL) {
        current_allocation_site =
            LoadNestedAllocationSite(CAST(current_allocation_site.value()));

        // Ensure we're consuming the AllocationSites in the correct order.
        CSA_DCHECK(
            this,
            TaggedEqual(LoadBoilerplate(CAST(current_allocation_site.value())),
                        item));
      }

      auto clone_and_next_allocation_site = CallBuiltin<PairT<Object, Object>>(
          Builtin::kCreateArrayFromSlowBoilerplateHelper, context,
          current_allocation_site.value(), item);

      clone = Projection<0>(clone_and_next_allocation_site);
      GotoIf(IsUndefined(clone.value()), bailout);
      current_allocation_site = Projection<1>(clone_and_next_allocation_site);
      Goto(cloned);
    }

    BIND(&is_object);
    {
      auto clone_and_next_allocation_site = CallBuiltin<PairT<Object, Object>>(
          Builtin::kCreateObjectFromSlowBoilerplateHelper, context,
          current_allocation_site.value(), item);
      clone = Projection<0>(clone_and_next_allocation_site);
      GotoIf(IsUndefined(clone.value()), bailout);
      current_allocation_site = Projection<1>(clone_and_next_allocation_site);
      Goto(cloned);
    }
  }

  void CloneElementsOfFixedArray(TNode<FixedArrayBase> elements,
                                 TNode<Smi> length, TNode<Int32T> elements_kind,
                                 TVariable<Object>& current_allocation_site,
                                 TNode<Context> context, Label* done,
                                 Label* bailout) {
    CSA_DCHECK(this, SmiNotEqual(length, SmiConstant(0)));

    auto loop_body = [&](TNode<IntPtrT> index) {
      TVARIABLE(Object, clone);
      Label cloned(this, &clone),
          done_with_element(this, &current_allocation_site);

      TNode<Object> element = LoadFixedArrayElement(CAST(elements), index);
      CloneIfObjectOrArray(element, clone, current_allocation_site, context,
                           &cloned, &done_with_element, bailout);

      BIND(&cloned);
      {
        StoreFixedArrayElement(CAST(elements), index, clone.value());
        Goto(&done_with_element);
      }

      BIND(&done_with_element);
    };
    VariableList loop_vars({&current_allocation_site}, zone());
    BuildFastLoop<IntPtrT>(loop_vars, IntPtrConstant(0),
                           PositiveSmiUntag(length), loop_body, 1,
                           LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);
    Goto(done);
  }
};

TF_BUILTIN(CreateArrayFromSlowBoilerplate, SlowBoilerplateCloneAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto feedback_vector = Parameter<FeedbackVector>(Descriptor::kFeedbackVector);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);

  Label call_runtime(this);

  TNode<Object> maybe_allocation_site =
      CAST(LoadFeedbackVectorSlot(feedback_vector, slot));
  GotoIfNot(HasBoilerplate(maybe_allocation_site), &call_runtime);

  TNode<AllocationSite> allocation_site = CAST(maybe_allocation_site);
  TNode<JSArray> boilerplate = CAST(LoadBoilerplate(allocation_site));

  {
    auto clone_and_next_allocation_site = CallBuiltin<PairT<Object, Object>>(
        Builtin::kCreateArrayFromSlowBoilerplateHelper, context,
        allocation_site, boilerplate);
    TNode<Object> result = Projection<0>(clone_and_next_allocation_site);

    GotoIf(IsUndefined(result), &call_runtime);
    Return(result);
  }

  BIND(&call_runtime);
  {
    auto boilerplate_descriptor = Parameter<ArrayBoilerplateDescription>(
        Descriptor::kBoilerplateDescriptor);
    auto flags = Parameter<Smi>(Descriptor::kFlags);
    TNode<Object> result =
        CallRuntime(Runtime::kCreateArrayLiteral, context, feedback_vector,
                    slot, boilerplate_descriptor, flags);
    Return(result);
  }
}

TF_BUILTIN(CreateObjectFromSlowBoilerplate, SlowBoilerplateCloneAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto feedback_vector = Parameter<FeedbackVector>(Descriptor::kFeedbackVector);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);

  Label call_runtime(this);

  TNode<Object> maybe_allocation_site =
      CAST(LoadFeedbackVectorSlot(feedback_vector, slot));
  GotoIfNot(HasBoilerplate(maybe_allocation_site), &call_runtime);

  TNode<AllocationSite> allocation_site = CAST(maybe_allocation_site);
  TNode<JSObject> boilerplate = LoadBoilerplate(allocation_site);

  {
    auto clone_and_next_allocation_site = CallBuiltin<PairT<Object, Object>>(
        Builtin::kCreateObjectFromSlowBoilerplateHelper, context,
        allocation_site, boilerplate);
    TNode<Object> result = Projection<0>(clone_and_next_allocation_site);

    GotoIf(IsUndefined(result), &call_runtime);
    Return(result);
  }

  BIND(&call_runtime);
  {
    auto boilerplate_descriptor = Parameter<ObjectBoilerplateDescription>(
        Descriptor::kBoilerplateDescriptor);
    auto flags = Parameter<Smi>(Descriptor::kFlags);
    TNode<Object> result =
        CallRuntime(Runtime::kCreateObjectLiteral, context, feedback_vector,
                    slot, boilerplate_descriptor, flags);
    Return(result);
  }
}

TF_BUILTIN(CreateArrayFromSlowBoilerplateHelper,
           SlowBoilerplateCloneAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto allocation_site = Parameter<AllocationSite>(Descriptor::kAllocationSite);
  auto boilerplate = Parameter<JSArray>(Descriptor::kBoilerplate);

  PerformStackCheck(context);

  TNode<FixedArrayBase> boilerplate_elements = LoadElements(boilerplate);
  TNode<Smi> length = LoadFixedArrayBaseLength(boilerplate_elements);

  // If the array contains other arrays (either directly or inside objects),
  // the AllocationSite tree is stored as a list (AllocationSite::nested_site)
  // in pre-order. See AllocationSiteUsageContext.
  TVARIABLE(Object, current_allocation_site);
  current_allocation_site = allocation_site;

  Label done(this, &current_allocation_site),
      bailout(this, &current_allocation_site, Label::kDeferred);

  // Keep in sync with ArrayLiteralBoilerplateBuilder::IsFastCloningSupported.
  // TODO(42204675): Detect this in advance when constructing the boilerplate.
  GotoIf(
      SmiAboveOrEqual(
          length,
          SmiConstant(ConstructorBuiltins::kMaximumClonedShallowArrayElements)),
      &bailout);

  // First clone the array as if was a simple, shallow array:
  TNode<JSArray> array;
  if (V8_ALLOCATION_SITE_TRACKING_BOOL) {
    array = CloneFastJSArray(context, boilerplate, allocation_site);
  } else {
    array = CloneFastJSArray(context, boilerplate);
  }

  // Then fix up each element by cloning it (if it's an object or an array).
  TNode<FixedArrayBase> elements = LoadElements(array);

  // If the boilerplate array is COW, it won't contain objects or arrays.
  GotoIf(TaggedEqual(LoadMap(elements), FixedCOWArrayMapConstant()), &done);

  // If the elements kind is not between PACKED_ELEMENTS and HOLEY_ELEMENTS, it
  // cannot contain objects or arrays.
  TNode<Int32T> elements_kind = LoadElementsKind(boilerplate);
  GotoIf(Uint32GreaterThan(
             Unsigned(Int32Sub(elements_kind, Int32Constant(PACKED_ELEMENTS))),
             Uint32Constant(HOLEY_ELEMENTS - PACKED_ELEMENTS)),
         &done);

  GotoIf(SmiEqual(length, SmiConstant(0)), &done);
  CloneElementsOfFixedArray(elements, length, elements_kind,
                            current_allocation_site, context, &done, &bailout);
  BIND(&done);
  { Return(array, current_allocation_site.value()); }

  BIND(&bailout);
  { Return(UndefinedConstant(), UndefinedConstant()); }
}

TF_BUILTIN(CreateObjectFromSlowBoilerplateHelper,
           SlowBoilerplateCloneAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto allocation_site = Parameter<AllocationSite>(Descriptor::kAllocationSite);
  auto boilerplate = Parameter<JSObject>(Descriptor::kBoilerplate);

  PerformStackCheck(context);

  TVARIABLE(Object, current_allocation_site);
  current_allocation_site = allocation_site;

  Label bailout(this, &current_allocation_site);

  // Keep in sync with ObjectLiteralBoilerplateBuilder::IsFastCloningSupported.
  // The property count needs to be below
  // ConstructorBuiltins::kMaximumClonedShallowObjectProperties.
  // CreateShallowObjectLiteral already bails out if all properties don't fit
  // in-object, so we don't need to check the property count here.
  // TODO(42204675): Detect this in advance when constructing the boilerplate.
  TNode<Int32T> elements_kind = LoadElementsKind(boilerplate);
  GotoIf(
      Int32GreaterThan(elements_kind, Int32Constant(LAST_FAST_ELEMENTS_KIND)),
      &bailout);

  constexpr bool kBailoutIfDictionaryPropertiesTrue = true;
  ConstructorBuiltinsAssembler constructor_assembler(state());
  TNode<JSObject> object =
      CAST(constructor_assembler.CreateShallowObjectLiteral(
          allocation_site, boilerplate, &bailout,
          kBailoutIfDictionaryPropertiesTrue));

  // Fix up the object properties and elements and consume the correct amount of
  // AllocationSites. To iterate the AllocationSites in the correct order, we
  // need to first iterate the in-object properties and then the elements.

  // Assert that there aren't any out of object properties (if there are, we
  // must have bailed out already):
  CSA_DCHECK(this, IsEmptyFixedArray(LoadFastProperties(boilerplate)));

  // In-object properties:
  {
    auto loop_body = [&](TNode<IntPtrT> offset) {
      TVARIABLE(Object, clone);
      Label cloned(this, &clone),
          done_with_field(this, &current_allocation_site);

      TNode<Object> field = LoadObjectField(object, offset);
      CloneIfObjectOrArray(field, clone, current_allocation_site, context,
                           &cloned, &done_with_field, &bailout);

      BIND(&cloned);
      {
        StoreObjectField(object, offset, clone.value());
        Goto(&done_with_field);
      }

      BIND(&done_with_field);
    };

    TNode<Map> boilerplate_map = LoadMap(boilerplate);
    TNode<IntPtrT> instance_size =
        TimesTaggedSize(LoadMapInstanceSizeInWords(boilerplate_map));
    VariableList loop_vars({&current_allocation_site}, zone());
    BuildFastLoop<IntPtrT>(loop_vars, IntPtrConstant(JSObject::kHeaderSize),
                           instance_size, loop_body, kTaggedSize,
                           LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);
  }

  // Elements:
  {
    Label done_with_elements(this);
    TNode<FixedArrayBase> elements = LoadElements(object);
    GotoIf(IsEmptyFixedArray(elements), &done_with_elements);

    TNode<Int32T> elements_kind = LoadElementsKind(object);
    // Object elements are never COW and never SMI_ELEMENTS etc.
    CloneElementsOfFixedArray(elements, LoadFixedArrayBaseLength(elements),
                              elements_kind, current_allocation_site, context,
                              &done_with_elements, &bailout);
    BIND(&done_with_elements);
  }

  Return(object, current_allocation_site.value());

  BIND(&bailout);
  {
    // We can't solve this case by calling into Runtime_CreateObjectLiteral,
    // since it's currently not suitable for creating a nested objects (e.g.,
    // doesn't return the next AllocationSite).
    Return(UndefinedConstant(), UndefinedConstant());
  }
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8
```