Response: The user wants me to summarize the functionality of the provided C++ code. This is the second part of a two-part file.

The code appears to be related to the implementation of the `Array` constructor in V8's JavaScript engine. It uses the CodeStubAssembler (CSA) to generate optimized machine code for different array creation scenarios.

Here's a breakdown of the code's responsibilities:

1. **Array Constructor Implementations:**  Provides different implementations for the `Array` constructor based on the number of arguments and the desired element type.
2. **Dispatch Logic:** Implements logic to dispatch to the appropriate array constructor based on the number of arguments provided.
3. **Allocation Site Optimization:** Incorporates allocation site feedback to optimize array creation, particularly for literal arrays.
4. **Slow Boilerplate Cloning:**  Handles the cloning of array and object literals that might contain nested objects or arrays, which requires recursive cloning.

I need to summarize these functionalities and provide JavaScript examples to illustrate the connection between the C++ code and JavaScript behavior.
这是V8 JavaScript引擎中 `Array` 构造函数的实现代码的第二部分。它主要负责处理各种情况下 `Array` 构造函数的调用，并使用优化的汇编代码来创建数组。

以下是其功能的归纳：

1. **`GenerateDispatchToArrayStub`**:  根据 `Array` 构造函数接收的参数数量（0个或1个），分派到不同的数组创建路径。这是一种性能优化，针对常见的情况提供更快的代码执行。

2. **`ArrayConstructorImpl`**:  这是 `Array` 构造函数的核心实现。它会检查是否使用了 `new` 关键字调用（`new.target`），以及是否有可用的分配站点信息（`allocation_site`）。根据这些信息，它会选择不同的数组创建策略：
    *   如果使用了 `new` 关键字并且有分配站点信息，则调用 `GenerateDispatchToArrayStub` 来分派到更优化的路径。
    *   如果没有分配站点信息，则调用 `GenerateDispatchToArrayStub` 并禁用分配站点优化。
    *   如果没有使用 `new` 关键字，则跳转到运行时函数 `GenerateArrayNArgumentsConstructor`。

3. **`GenerateConstructor`**:  这是一个通用的数组构造函数生成器。它根据传入的数组大小、元素类型和分配站点信息来创建数组。它会区分数组大小是Smi（小整数）还是其他类型，并根据元素类型判断是否需要调用运行时函数来处理更大的数组或特定的元素类型。

4. **`GenerateArrayNoArgumentConstructor`**:  专门用于创建没有参数的数组，例如 `new Array()` 或 `[]`。它会根据指定的元素类型（`kind`）和分配站点模式创建具有预分配空间但长度为0的数组。

5. **`GenerateArraySingleArgumentConstructor`**:  用于创建只有一个参数的数组，例如 `new Array(5)` 或 `[element]`。如果参数是数字，它将创建一个指定长度的空数组；如果参数是其他类型，它将创建一个包含该单个元素的数组。

6. **`GenerateArrayNArgumentsConstructor`**:  用于创建具有多个参数的数组，例如 `new Array(1, 2, 3)` 或 `[1, 2, 3]`。它将所有传入的参数作为数组的元素。

7. **`ArrayNArgumentsConstructor`**:  这是 `Array` 构造函数在接收多个参数时的入口点。它直接调用 `GenerateArrayNArgumentsConstructor`。

8. **`SlowBoilerplateCloneAssembler` 和相关的 Builtin**:  这部分代码处理从“慢速样板”（Slow Boilerplate）创建数组和对象的情况。慢速样板通常用于字面量创建，当字面量包含对象或数组时，需要进行深度克隆以确保独立性。
    *   `CreateArrayFromSlowBoilerplate` 和 `CreateObjectFromSlowBoilerplate`：是创建字面量数组和对象的入口点，它们尝试从反馈向量中加载分配站点信息，如果存在则调用助手函数进行快速克隆，否则调用运行时函数。
    *   `CreateArrayFromSlowBoilerplateHelper` 和 `CreateObjectFromSlowBoilerplateHelper`：执行实际的深度克隆操作。它们会递归地克隆数组和对象中的元素或属性，确保嵌套的对象和数组也被正确复制。

**与 JavaScript 的关系和示例：**

这段 C++ 代码直接实现了 JavaScript 中 `Array` 构造函数的行为。以下是一些 JavaScript 示例，展示了代码中不同部分的对应功能：

1. **`GenerateDispatchToArrayStub` 和 `ArrayConstructorImpl`**:

    ```javascript
    const arr1 = new Array(); // 对应 GenerateArrayNoArgumentConstructor
    const arr2 = new Array(5); // 对应 GenerateArraySingleArgumentConstructor
    const arr3 = new Array(1, 2, 3); // 对应 GenerateArrayNArgumentsConstructor
    ```

2. **`GenerateArrayNoArgumentConstructor`**:

    ```javascript
    const emptyArray1 = new Array(); // 创建一个空数组
    const emptyArray2 = [];         // 同样创建一个空数组
    ```

3. **`GenerateArraySingleArgumentConstructor`**:

    ```javascript
    const arrayWithSize = new Array(10); // 创建一个长度为 10 的空数组
    const arrayWithElement = new Array('hello'); // 创建一个包含 "hello" 的数组
    const arrayLiteral = ['world']; // 同样创建一个包含 "world" 的数组
    ```

4. **`GenerateArrayNArgumentsConstructor`**:

    ```javascript
    const multiElementArray1 = new Array(1, 'a', true);
    const multiElementArray2 = [1, 'a', true];
    ```

5. **`SlowBoilerplateCloneAssembler` 和相关的 Builtin**:

    ```javascript
    const nestedArray1 = [1, 2, { a: 3 }]; // 创建包含对象的数组
    const nestedArray2 = [4, [5, 6]];     // 创建包含数组的数组

    // 当创建类似上面的字面量时，V8 可能会使用 SlowBoilerplateCloneAssembler
    // 来确保嵌套的对象和数组被正确地克隆，而不是共享引用。
    const clonedObject = { ...nestedArray1[2] }; // 浅拷贝，但原始创建可能涉及深拷贝
    const clonedArray = [...nestedArray2[1]];    // 浅拷贝，但原始创建可能涉及深拷贝
    ```

总而言之，这段 C++ 代码是 V8 引擎实现 JavaScript `Array` 构造函数的核心部分，它通过优化的汇编代码来高效地创建和初始化各种类型的数组，并处理了字面量创建中可能出现的复杂情况，例如嵌套的对象和数组的克隆。

Prompt: 
```
这是目录为v8/src/builtins/builtins-array-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
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

"""


```