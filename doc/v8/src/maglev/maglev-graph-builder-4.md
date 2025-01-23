Response: The user wants a summary of the C++ source code file `v8/src/maglev/maglev-graph-builder.cc`, specifically part 5 of 9. The summary should focus on the functionalities implemented in this part and whether they relate to JavaScript. If so, a JavaScript example should be provided.

Let's break down the code snippet to identify its key functionalities:

1. **Property Access Optimization:** This part heavily deals with optimizing property access (loads and stores) based on feedback. It includes:
    - Trying to reuse previously loaded properties (caching).
    - Handling different feedback states (insufficient, named access, element access).
    - Building specialized nodes for fast property access based on feedback.
    - Falling back to generic property access if feedback is insufficient or specialized access fails.
    - Recording known properties to enable reuse.
    - Handling both named and keyed properties.
    - Special handling for property access in super calls.
    - Optimization for enumerated keys during `for...in` loops.

2. **Module Variable Access:**  Functions for loading and storing module variables.

3. **Global Variable Access:**  Functions for loading global variables.

4. **Constant Handling:**  Functions to retrieve constants.

5. **Inlining:** Logic for deciding whether to inline function calls and for building the inlined code.

6. **Built-in Function Reduction:** Attempts to optimize calls to specific built-in functions like `Array.isArray` and `Array.prototype.forEach`.

7. **Array Iterator Optimization:**  Optimizes the `next()` method of array iterators.

Now, let's consider the relationship with JavaScript and provide examples:

- **Property Access:** This is fundamental to JavaScript. Accessing properties like `object.property` or `object['property']` are the core operations being optimized here.
- **Module Variables:**  JavaScript modules use `import` and `export`. The code handles accessing these exported/imported variables.
- **Global Variables:**  Accessing global variables like `window.variable` or simply `variable` (if in the global scope) is covered here.
- **Inlining:**  JavaScript engines inline function calls to improve performance. The code handles the process of inserting the body of a called function directly into the caller.
- **Built-in Function Optimization:**  JavaScript relies heavily on built-in functions. Optimizing calls to functions like `Array.isArray` or array iteration methods significantly impacts performance.
- **Array Iterators:**  Used in `for...of` loops and when manually iterating over arrays.

Based on this analysis, I can now generate the summary.
这是 `v8/src/maglev/maglev-graph-builder.cc` 文件的第五部分，主要负责构建 Maglev 图中与 **属性访问优化** 相关的节点，以及一些与 **模块变量、全局变量访问、常量处理、函数内联和特定内置函数优化** 相关的功能。

**主要功能归纳:**

1. **属性访问优化 (Property Access Optimization):** 这部分是核心功能，致力于根据运行时反馈信息，为属性的读取和写入构建高效的图节点。
   - **尝试重用已知的属性加载 (TryReuseKnownPropertyLoad):**  如果之前已经加载过某个对象的属性，并且对象和属性名没有变化，则尝试重用之前的加载结果，避免重复计算。
   - **基于反馈信息构建 Named Access 节点 (TryBuildNamedAccess):** 根据反馈信息（例如，对象的 Map 信息、属性的访问类型等）构建优化的属性访问节点，例如直接读取对象特定偏移量的字段。
   - **处理不同类型的属性访问 (TryBuildPropertyLoad, TryBuildPropertyStore):**  区分是加载还是存储属性，以及是否是任何类型的存储。
   - **处理通用的属性访问 (build_generic_access):**  当没有足够的反馈信息或者无法进行优化时，会构建通用的属性访问节点。
   - **记录已知的属性 (RecordKnownProperty):**  记录已经加载或存储的属性，以便后续的重用优化。
   - **处理 super 关键字的属性访问 (VisitGetNamedPropertyFromSuper):**  针对 `super` 关键字的属性访问构建相应的节点。
   - **优化 `for...in` 循环中的键值访问 (TryBuildGetKeyedPropertyWithEnumeratedKey):**  针对 `for...in` 循环中遍历对象属性时的键值访问进行优化。
   - **构建字符串长度加载节点 (BuildLoadStringLength):**  专门处理加载字符串长度的情况。

2. **模块变量访问 (Module Variable Access):**  包含加载和存储模块变量的功能。
   - **加载模块变量 (VisitLdaModuleVariable):**  构建加载模块变量的节点，需要根据模块的层级深度和变量索引来定位。
   - **存储模块变量 (VisitStaModuleVariable):**  构建存储模块变量的节点。
   - **获取指定深度的 Context (GetContextAtDepth):**  辅助模块变量访问，获取指定作用域层级的上下文。

3. **全局变量访问 (Global Variable Access):**  处理全局变量的加载。
   - **构建加载全局变量的节点 (BuildLoadGlobal):**  根据反馈信息构建加载全局变量的节点。

4. **常量处理 (Constant Handling):**  提供获取常量的功能。
   - **获取常量 (GetConstant, GetTrustedConstant):**  从常量池中获取常量值，包括 Smi 和堆对象。

5. **函数内联 (Inlining):**  包含决定是否内联函数调用以及构建内联代码的逻辑。
   - **判断是否应该内联 (ShouldInlineCall):**  根据函数的大小、调用频率、内联深度等因素判断是否应该进行内联。
   - **尝试构建内联调用 (TryBuildInlinedCall):**  如果决定内联，则创建新的编译单元和图构建器，构建内联函数的代码。

6. **内置函数优化 (Built-in Function Reduction):**  尝试优化对特定内置函数的调用。
   - **优化 `Array.isArray` (TryReduceArrayIsArray):**  尝试基于参数的类型信息直接返回布尔值，避免实际的函数调用。
   - **优化 `Array.prototype.forEach` (TryReduceArrayForEach):**  尝试将 `forEach` 循环展开为 Maglev 图中的一系列操作，以提高性能。
   - **优化 `Array.prototype[Symbol.iterator].prototype.next` (TryReduceArrayIteratorPrototypeNext):**  尝试优化数组迭代器的 `next` 方法，特别是在 `for...of` 循环中。

**与 JavaScript 的关系及示例:**

这部分代码与 JavaScript 的性能优化密切相关。Maglev 是 V8 引擎的一个中间层，它将 JavaScript 代码转换为一种更易于优化的中间表示。这里的功能直接影响 JavaScript 代码的执行效率。

**JavaScript 示例:**

```javascript
function processArray(arr) {
  let sum = 0;
  for (let i = 0; i < arr.length; i++) {
    sum += arr[i]; // 这里会触发属性访问优化
  }
  return sum;
}

const myArray = [1, 2, 3, 4, 5];
processArray(myArray);

console.log(Array.isArray(myArray)); // 这里会触发 Array.isArray 的优化

myArray.forEach(element => { // 这里会触发 Array.prototype.forEach 的优化
  console.log(element);
});

for (const item of myArray) { // 这里会触发 Array Iterator 的优化
  console.log(item);
}

import { counter } from './module.js'; // 这里会触发模块变量访问

console.log(globalThis.Math); // 这里会触发全局变量访问

function inlineMe() {
  return 1 + 1;
}

function caller() {
  return inlineMe(); // 这里可能会触发函数内联
}
```

**代码段中出现的关键概念与 JavaScript 的对应关系：**

* **`TryBuildNamedAccess`:**  对应 JavaScript 中访问对象属性，如 `object.property`。
* **`TryBuildPropertyLoad` / `TryBuildPropertyStore`:** 对应 JavaScript 中读取或写入对象属性。
* **`VisitLdaModuleVariable` / `VisitStaModuleVariable`:** 对应 JavaScript ES 模块中的 `import` 和 `export` 语句。
* **`BuildLoadGlobal`:** 对应 JavaScript 中访问全局变量，如 `window.innerWidth` 或直接使用 `Math` 对象。
* **`TryReduceArrayIsArray`:** 对应 JavaScript 中的 `Array.isArray()` 方法。
* **`TryReduceArrayForEach`:** 对应 JavaScript 中的 `Array.prototype.forEach()` 方法。
* **`TryReduceArrayIteratorPrototypeNext`:** 对应 JavaScript 中 `for...of` 循环或者手动调用数组迭代器的 `next()` 方法。
* **`ShouldInlineCall` / `TryBuildInlinedCall`:** 对应 JavaScript 引擎对函数调用进行内联优化的过程。

总而言之，这部分 C++ 代码的核心目标是提升 JavaScript 代码中常见的操作（如属性访问、模块/全局变量访问、特定内置函数调用等）的执行效率，通过在 Maglev 图构建阶段进行优化，减少运行时开销。

### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共9部分，请归纳一下它的功能
```

### 源代码
```
feedback.name(), access_info, access_mode);
    } else {
      result = TryBuildPropertyLoad(receiver, lookup_start_object,
                                    feedback.name(), access_info);
    }

    switch (result.kind()) {
      case ReduceResult::kDoneWithValue:
      case ReduceResult::kDoneWithoutValue:
        DCHECK_EQ(result.HasValue(), !is_any_store);
        if (!done.has_value()) {
          // We initialize the label {done} lazily on the first possible path.
          // If no possible path exists, it is guaranteed that BuildCheckMaps
          // emitted an unconditional deopt and we return DoneWithAbort at the
          // end. We need one extra predecessor to jump from the generic case.
          const int possible_predecessors = access_info_count - i + 1;
          if (is_any_store) {
            done.emplace(&sub_graph, possible_predecessors);
          } else {
            ret_val.emplace(0);
            done.emplace(
                &sub_graph, possible_predecessors,
                std::initializer_list<MaglevSubGraphBuilder::Variable*>{
                    &*ret_val});
          }
        }

        if (!is_any_store) {
          sub_graph.set(*ret_val, result.value());
        }
        sub_graph.Goto(&*done);
        break;
      case ReduceResult::kDoneWithAbort:
        break;
      case ReduceResult::kFail:
        if (!generic_access.has_value()) {
          // Conservatively assume that all remaining branches can go into the
          // generic path, as we have to initialize the predecessors upfront.
          // TODO(pthier): Find a better way to do that.
          generic_access.emplace(&sub_graph, access_info_count - i);
        }
        sub_graph.Goto(&*generic_access);
        break;
      default:
        UNREACHABLE();
    }

    if (check_next_map.has_value()) {
      sub_graph.Bind(&*check_next_map);
    }
  }

  if (generic_access.has_value() &&
      !sub_graph.TrimPredecessorsAndBind(&*generic_access).IsDoneWithAbort()) {
    ReduceResult generic_result = build_generic_access();
    DCHECK(generic_result.IsDone());
    DCHECK_EQ(generic_result.IsDoneWithValue(), !is_any_store);
    if (!done.has_value()) {
      return is_any_store ? ReduceResult::Done() : generic_result.value();
    }
    if (!is_any_store) {
      sub_graph.set(*ret_val, generic_result.value());
    }
    sub_graph.Goto(&*done);
  }

  if (done.has_value()) {
    RETURN_IF_ABORT(sub_graph.TrimPredecessorsAndBind(&*done));
    return is_any_store ? ReduceResult::Done() : sub_graph.get(*ret_val);
  } else {
    return ReduceResult::DoneWithAbort();
  }
}

void MaglevGraphBuilder::RecordKnownProperty(
    ValueNode* lookup_start_object, KnownNodeAspects::LoadedPropertyMapKey key,
    ValueNode* value, bool is_const, compiler::AccessMode access_mode) {
  DCHECK(!value->properties().is_conversion());
  KnownNodeAspects::LoadedPropertyMap& loaded_properties =
      is_const ? known_node_aspects().loaded_constant_properties
               : known_node_aspects().loaded_properties;
  // Try to get loaded_properties[key] if it already exists, otherwise
  // construct loaded_properties[key] = ZoneMap{zone()}.
  auto& props_for_key =
      loaded_properties.try_emplace(key, zone()).first->second;

  if (!is_const && IsAnyStore(access_mode)) {
    if (is_loop_effect_tracking()) {
      loop_effects_->keys_cleared.insert(key);
    }
    // We don't do any aliasing analysis, so stores clobber all other cached
    // loads of a property with that key. We only need to do this for
    // non-constant properties, since constant properties are known not to
    // change and therefore can't be clobbered.
    // TODO(leszeks): Do some light aliasing analysis here, e.g. checking
    // whether there's an intersection of known maps.
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  * Removing all non-constant cached ";
      switch (key.type()) {
        case KnownNodeAspects::LoadedPropertyMapKey::kName:
          std::cout << "properties with name " << *key.name().object();
          break;
        case KnownNodeAspects::LoadedPropertyMapKey::kElements:
          std::cout << "Elements";
          break;
        case KnownNodeAspects::LoadedPropertyMapKey::kTypedArrayLength:
          std::cout << "TypedArray length";
          break;
        case KnownNodeAspects::LoadedPropertyMapKey::kStringLength:
          std::cout << "String length";
          break;
      }
      std::cout << std::endl;
    }
    props_for_key.clear();
  }

  if (v8_flags.trace_maglev_graph_building) {
    std::cout << "  * Recording " << (is_const ? "constant" : "non-constant")
              << " known property "
              << PrintNodeLabel(graph_labeller(), lookup_start_object) << ": "
              << PrintNode(graph_labeller(), lookup_start_object) << " [";
    switch (key.type()) {
      case KnownNodeAspects::LoadedPropertyMapKey::kName:
        std::cout << *key.name().object();
        break;
      case KnownNodeAspects::LoadedPropertyMapKey::kElements:
        std::cout << "Elements";
        break;
      case KnownNodeAspects::LoadedPropertyMapKey::kTypedArrayLength:
        std::cout << "TypedArray length";
        break;
      case KnownNodeAspects::LoadedPropertyMapKey::kStringLength:
        std::cout << "String length";
        break;
    }
    std::cout << "] = " << PrintNodeLabel(graph_labeller(), value) << ": "
              << PrintNode(graph_labeller(), value) << std::endl;
  }

  if (IsAnyStore(access_mode) && !is_const && is_loop_effect_tracking()) {
    auto updated = props_for_key.emplace(lookup_start_object, value);
    if (updated.second) {
      loop_effects_->objects_written.insert(lookup_start_object);
    } else if (updated.first->second != value) {
      updated.first->second = value;
      loop_effects_->objects_written.insert(lookup_start_object);
    }
  } else {
    props_for_key[lookup_start_object] = value;
  }
}

ReduceResult MaglevGraphBuilder::TryReuseKnownPropertyLoad(
    ValueNode* lookup_start_object, compiler::NameRef name) {
  if (ReduceResult result = TryFindLoadedProperty(
          known_node_aspects().loaded_properties, lookup_start_object, name);
      result.IsDone()) {
    if (v8_flags.trace_maglev_graph_building && result.IsDoneWithValue()) {
      std::cout << "  * Reusing non-constant loaded property "
                << PrintNodeLabel(graph_labeller(), result.value()) << ": "
                << PrintNode(graph_labeller(), result.value()) << std::endl;
    }
    return result;
  }
  if (ReduceResult result =
          TryFindLoadedProperty(known_node_aspects().loaded_constant_properties,
                                lookup_start_object, name);
      result.IsDone()) {
    if (v8_flags.trace_maglev_graph_building && result.IsDoneWithValue()) {
      std::cout << "  * Reusing constant loaded property "
                << PrintNodeLabel(graph_labeller(), result.value()) << ": "
                << PrintNode(graph_labeller(), result.value()) << std::endl;
    }
    return result;
  }
  return ReduceResult::Fail();
}

ValueNode* MaglevGraphBuilder::BuildLoadStringLength(ValueNode* string) {
  if (ReduceResult result = TryFindLoadedProperty(
          known_node_aspects().loaded_constant_properties, string,
          KnownNodeAspects::LoadedPropertyMapKey::StringLength());
      result.IsDone()) {
    if (v8_flags.trace_maglev_graph_building && result.IsDoneWithValue()) {
      std::cout << "  * Reusing constant [String length]"
                << PrintNodeLabel(graph_labeller(), result.value()) << ": "
                << PrintNode(graph_labeller(), result.value()) << std::endl;
    }
    return result.value();
  }
  ValueNode* result = AddNewNode<StringLength>({string});
  RecordKnownProperty(string,
                      KnownNodeAspects::LoadedPropertyMapKey::StringLength(),
                      result, true, compiler::AccessMode::kLoad);
  return result;
}

template <typename GenericAccessFunc>
ReduceResult MaglevGraphBuilder::TryBuildLoadNamedProperty(
    ValueNode* receiver, ValueNode* lookup_start_object, compiler::NameRef name,
    compiler::FeedbackSource& feedback_source,
    GenericAccessFunc&& build_generic_access) {
  const compiler::ProcessedFeedback& processed_feedback =
      broker()->GetFeedbackForPropertyAccess(feedback_source,
                                             compiler::AccessMode::kLoad, name);
  switch (processed_feedback.kind()) {
    case compiler::ProcessedFeedback::kInsufficient:
      return EmitUnconditionalDeopt(
          DeoptimizeReason::kInsufficientTypeFeedbackForGenericNamedAccess);
    case compiler::ProcessedFeedback::kNamedAccess: {
      RETURN_IF_DONE(TryReuseKnownPropertyLoad(lookup_start_object, name));
      return TryBuildNamedAccess(
          receiver, lookup_start_object, processed_feedback.AsNamedAccess(),
          feedback_source, compiler::AccessMode::kLoad, build_generic_access);
    }
    default:
      return ReduceResult::Fail();
  }
}

ReduceResult MaglevGraphBuilder::TryBuildLoadNamedProperty(
    ValueNode* receiver, compiler::NameRef name,
    compiler::FeedbackSource& feedback_source) {
  auto build_generic_access = [this, &receiver, &name, &feedback_source]() {
    ValueNode* context = GetContext();
    return AddNewNode<LoadNamedGeneric>({context, receiver}, name,
                                        feedback_source);
  };
  return TryBuildLoadNamedProperty(receiver, receiver, name, feedback_source,
                                   build_generic_access);
}

void MaglevGraphBuilder::VisitGetNamedProperty() {
  // GetNamedProperty <object> <name_index> <slot>
  ValueNode* object = LoadRegister(0);
  compiler::NameRef name = GetRefOperand<Name>(1);
  FeedbackSlot slot = GetSlotOperand(2);
  compiler::FeedbackSource feedback_source{feedback(), slot};
  PROCESS_AND_RETURN_IF_DONE(
      TryBuildLoadNamedProperty(object, name, feedback_source), SetAccumulator);
  // Create a generic load in the fallthrough.
  ValueNode* context = GetContext();
  SetAccumulator(
      AddNewNode<LoadNamedGeneric>({context, object}, name, feedback_source));
}

ValueNode* MaglevGraphBuilder::GetConstant(compiler::ObjectRef ref) {
  if (ref.IsSmi()) return GetSmiConstant(ref.AsSmi());
  compiler::HeapObjectRef constant = ref.AsHeapObject();

  if (IsThinString(*constant.object())) {
    constant = MakeRefAssumeMemoryFence(
        broker(), Cast<ThinString>(*constant.object())->actual());
  }

  auto root_index = broker()->FindRootIndex(constant);
  if (root_index.has_value()) {
    return GetRootConstant(*root_index);
  }

  auto it = graph_->constants().find(constant);
  if (it == graph_->constants().end()) {
    Constant* node = CreateNewConstantNode<Constant>(0, constant);
    graph_->constants().emplace(constant, node);
    return node;
  }
  return it->second;
}

ValueNode* MaglevGraphBuilder::GetTrustedConstant(compiler::HeapObjectRef ref,
                                                  IndirectPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  auto it = graph_->trusted_constants().find(ref);
  if (it == graph_->trusted_constants().end()) {
    TrustedConstant* node = CreateNewConstantNode<TrustedConstant>(0, ref, tag);
    graph_->trusted_constants().emplace(ref, node);
    return node;
  }
  SBXCHECK_EQ(it->second->tag(), tag);
  return it->second;
#else
  return GetConstant(ref);
#endif
}

void MaglevGraphBuilder::VisitGetNamedPropertyFromSuper() {
  // GetNamedPropertyFromSuper <receiver> <name_index> <slot>
  ValueNode* receiver = LoadRegister(0);
  ValueNode* home_object = GetAccumulator();
  compiler::NameRef name = GetRefOperand<Name>(1);
  FeedbackSlot slot = GetSlotOperand(2);
  compiler::FeedbackSource feedback_source{feedback(), slot};
  // {home_object} is guaranteed to be a HeapObject.
  ValueNode* home_object_map =
      BuildLoadTaggedField(home_object, HeapObject::kMapOffset);
  ValueNode* lookup_start_object =
      BuildLoadTaggedField(home_object_map, Map::kPrototypeOffset);

  auto build_generic_access = [this, &receiver, &lookup_start_object, &name,
                               &feedback_source]() {
    ValueNode* context = GetContext();
    return AddNewNode<LoadNamedFromSuperGeneric>(
        {context, receiver, lookup_start_object}, name, feedback_source);
  };

  PROCESS_AND_RETURN_IF_DONE(
      TryBuildLoadNamedProperty(receiver, lookup_start_object, name,
                                feedback_source, build_generic_access),
      SetAccumulator);
  // Create a generic load.
  SetAccumulator(build_generic_access());
}

bool MaglevGraphBuilder::TryBuildGetKeyedPropertyWithEnumeratedKey(
    ValueNode* object, const compiler::FeedbackSource& feedback_source,
    const compiler::ProcessedFeedback& processed_feedback) {
  if (current_for_in_state.index != nullptr &&
      current_for_in_state.enum_cache_indices != nullptr &&
      current_for_in_state.key == current_interpreter_frame_.accumulator()) {
    bool speculating_receiver_map_matches = false;
    if (current_for_in_state.receiver != object) {
      // When the feedback is uninitialized, it is either a keyed load which
      // always hits the enum cache, or a keyed load that had never been
      // reached. In either case, we can check the map of the receiver and use
      // the enum cache if the map match the {cache_type}.
      if (processed_feedback.kind() !=
          compiler::ProcessedFeedback::kInsufficient) {
        return false;
      }
      BuildCheckHeapObject(object);
      speculating_receiver_map_matches = true;
    }

    if (current_for_in_state.receiver_needs_map_check ||
        speculating_receiver_map_matches) {
      auto* receiver_map = BuildLoadTaggedField(object, HeapObject::kMapOffset);
      AddNewNode<CheckDynamicValue>(
          {receiver_map, current_for_in_state.cache_type});
      if (current_for_in_state.receiver == object) {
        current_for_in_state.receiver_needs_map_check = false;
      }
    }
    // TODO(leszeks): Cache the field index per iteration.
    auto* field_index = BuildLoadFixedArrayElement(
        current_for_in_state.enum_cache_indices, current_for_in_state.index);
    SetAccumulator(
        AddNewNode<LoadTaggedFieldByFieldIndex>({object, field_index}));
    return true;
  }
  return false;
}

void MaglevGraphBuilder::BuildGetKeyedProperty(
    ValueNode* object, const compiler::FeedbackSource& feedback_source,
    const compiler::ProcessedFeedback& processed_feedback) {
  if (TryBuildGetKeyedPropertyWithEnumeratedKey(object, feedback_source,
                                                processed_feedback)) {
    return;
  }

  auto build_generic_access = [this, object, &feedback_source]() {
    ValueNode* context = GetContext();
    ValueNode* key = GetAccumulator();
    return AddNewNode<GetKeyedGeneric>({context, object, key}, feedback_source);
  };

  switch (processed_feedback.kind()) {
    case compiler::ProcessedFeedback::kInsufficient:
      RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
          DeoptimizeReason::kInsufficientTypeFeedbackForGenericKeyedAccess));

    case compiler::ProcessedFeedback::kElementAccess: {
      // Get the accumulator without conversion. TryBuildElementAccess
      // will try to pick the best representation.
      ValueNode* index = current_interpreter_frame_.accumulator();
      ReduceResult result = TryBuildElementAccess(
          object, index, processed_feedback.AsElementAccess(), feedback_source,
          build_generic_access);
      PROCESS_AND_RETURN_IF_DONE(result, SetAccumulator);
      break;
    }

    case compiler::ProcessedFeedback::kNamedAccess: {
      ValueNode* key = GetAccumulator();
      compiler::NameRef name = processed_feedback.AsNamedAccess().name();
      RETURN_VOID_IF_ABORT(BuildCheckValue(key, name));

      ReduceResult result = TryReuseKnownPropertyLoad(object, name);
      PROCESS_AND_RETURN_IF_DONE(result, SetAccumulator);

      result = TryBuildNamedAccess(
          object, object, processed_feedback.AsNamedAccess(), feedback_source,
          compiler::AccessMode::kLoad, build_generic_access);
      PROCESS_AND_RETURN_IF_DONE(result, SetAccumulator);
      break;
    }

    default:
      break;
  }

  // Create a generic load in the fallthrough.
  SetAccumulator(build_generic_access());
}

void MaglevGraphBuilder::VisitGetKeyedProperty() {
  // GetKeyedProperty <object> <slot>
  ValueNode* object = LoadRegister(0);
  // TODO(leszeks): We don't need to tag the key if it's an Int32 and a simple
  // monomorphic element load.
  FeedbackSlot slot = GetSlotOperand(1);
  compiler::FeedbackSource feedback_source{feedback(), slot};

  const compiler::ProcessedFeedback* processed_feedback =
      &broker()->GetFeedbackForPropertyAccess(
          feedback_source, compiler::AccessMode::kLoad, std::nullopt);
  if (processed_feedback->kind() ==
          compiler::ProcessedFeedback::kElementAccess &&
      processed_feedback->AsElementAccess().transition_groups().empty()) {
    if (auto constant = TryGetConstant(GetAccumulator());
        constant.has_value() && constant->IsName()) {
      compiler::NameRef name = constant->AsName();
      if (name.IsUniqueName() && !name.object()->IsArrayIndex()) {
        processed_feedback =
            &processed_feedback->AsElementAccess().Refine(broker(), name);
      }
    }
  }

  BuildGetKeyedProperty(object, feedback_source, *processed_feedback);
}

void MaglevGraphBuilder::VisitGetEnumeratedKeyedProperty() {
  // GetEnumeratedKeyedProperty <object> <enum_index> <cache_type> <slot>
  ValueNode* object = LoadRegister(0);
  FeedbackSlot slot = GetSlotOperand(3);
  compiler::FeedbackSource feedback_source{feedback(), slot};

  const compiler::ProcessedFeedback& processed_feedback =
      broker()->GetFeedbackForPropertyAccess(
          feedback_source, compiler::AccessMode::kLoad, std::nullopt);

  BuildGetKeyedProperty(object, feedback_source, processed_feedback);
}

void MaglevGraphBuilder::VisitLdaModuleVariable() {
  // LdaModuleVariable <cell_index> <depth>
  int cell_index = iterator_.GetImmediateOperand(0);
  size_t depth = iterator_.GetUnsignedImmediateOperand(1);
  ValueNode* context = GetContextAtDepth(GetContext(), depth);

  ValueNode* module = LoadAndCacheContextSlot(
      context, Context::EXTENSION_INDEX, kImmutable, ContextKind::kDefault);
  ValueNode* exports_or_imports;
  if (cell_index > 0) {
    exports_or_imports =
        BuildLoadTaggedField(module, SourceTextModule::kRegularExportsOffset);
    // The actual array index is (cell_index - 1).
    cell_index -= 1;
  } else {
    exports_or_imports =
        BuildLoadTaggedField(module, SourceTextModule::kRegularImportsOffset);
    // The actual array index is (-cell_index - 1).
    cell_index = -cell_index - 1;
  }
  ValueNode* cell = BuildLoadFixedArrayElement(exports_or_imports, cell_index);
  SetAccumulator(BuildLoadTaggedField(cell, Cell::kValueOffset));
}

ValueNode* MaglevGraphBuilder::GetContextAtDepth(ValueNode* context,
                                                 size_t depth) {
  MinimizeContextChainDepth(&context, &depth);

  if (compilation_unit_->info()->specialize_to_function_context()) {
    compiler::OptionalContextRef maybe_ref =
        FunctionContextSpecialization::TryToRef(compilation_unit_, context,
                                                &depth);
    if (maybe_ref.has_value()) {
      context = GetConstant(maybe_ref.value());
    }
  }

  for (size_t i = 0; i < depth; i++) {
    context = LoadAndCacheContextSlot(context, Context::PREVIOUS_INDEX,
                                      kImmutable, ContextKind::kDefault);
  }
  return context;
}

void MaglevGraphBuilder::VisitStaModuleVariable() {
  // StaModuleVariable <cell_index> <depth>
  int cell_index = iterator_.GetImmediateOperand(0);
  if (V8_UNLIKELY(cell_index < 0)) {
    // TODO(verwaest): Make this fail as well.
    CHECK(BuildCallRuntime(Runtime::kAbort,
                           {GetSmiConstant(static_cast<int>(
                               AbortReason::kUnsupportedModuleOperation))})
              .IsDone());
    return;
  }

  size_t depth = iterator_.GetUnsignedImmediateOperand(1);
  ValueNode* context = GetContextAtDepth(GetContext(), depth);

  ValueNode* module = LoadAndCacheContextSlot(
      context, Context::EXTENSION_INDEX, kImmutable, ContextKind::kDefault);
  ValueNode* exports =
      BuildLoadTaggedField(module, SourceTextModule::kRegularExportsOffset);
  // The actual array index is (cell_index - 1).
  cell_index -= 1;
  ValueNode* cell = BuildLoadFixedArrayElement(exports, cell_index);
  BuildStoreTaggedField(cell, GetAccumulator(), Cell::kValueOffset,
                        StoreTaggedMode::kDefault);
}

void MaglevGraphBuilder::BuildLoadGlobal(
    compiler::NameRef name, compiler::FeedbackSource& feedback_source,
    TypeofMode typeof_mode) {
  const compiler::ProcessedFeedback& access_feedback =
      broker()->GetFeedbackForGlobalAccess(feedback_source);

  if (access_feedback.IsInsufficient()) {
    RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
        DeoptimizeReason::kInsufficientTypeFeedbackForGenericGlobalAccess));
  }

  const compiler::GlobalAccessFeedback& global_access_feedback =
      access_feedback.AsGlobalAccess();
  PROCESS_AND_RETURN_IF_DONE(TryBuildGlobalLoad(global_access_feedback),
                             SetAccumulator);

  ValueNode* context = GetContext();
  SetAccumulator(
      AddNewNode<LoadGlobal>({context}, name, feedback_source, typeof_mode));
}

void MaglevGraphBuilder::VisitSetNamedProperty() {
  // SetNamedProperty <object> <name_index> <slot>
  ValueNode* object = LoadRegister(0);
  compiler::NameRef name = GetRefOperand<Name>(1);
  FeedbackSlot slot = GetSlotOperand(2);
  compiler::FeedbackSource feedback_source{feedback(), slot};

  const compiler::ProcessedFeedback& processed_feedback =
      broker()->GetFeedbackForPropertyAccess(
          feedback_source, compiler::AccessMode::kStore, name);

  auto build_generic_access = [this, object, &name, &feedback_source]() {
    ValueNode* context = GetContext();
    ValueNode* value = GetAccumulator();
    AddNewNode<SetNamedGeneric>({context, object, value}, name,
                                feedback_source);
    return ReduceResult::Done();
  };

  switch (processed_feedback.kind()) {
    case compiler::ProcessedFeedback::kInsufficient:
      RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
          DeoptimizeReason::kInsufficientTypeFeedbackForGenericNamedAccess));

    case compiler::ProcessedFeedback::kNamedAccess:
      RETURN_VOID_IF_DONE(TryBuildNamedAccess(
          object, object, processed_feedback.AsNamedAccess(), feedback_source,
          compiler::AccessMode::kStore, build_generic_access));
      break;
    default:
      break;
  }

  // Create a generic store in the fallthrough.
  RETURN_VOID_IF_ABORT(build_generic_access());
}

void MaglevGraphBuilder::VisitDefineNamedOwnProperty() {
  // DefineNamedOwnProperty <object> <name_index> <slot>
  ValueNode* object = LoadRegister(0);
  compiler::NameRef name = GetRefOperand<Name>(1);
  FeedbackSlot slot = GetSlotOperand(2);
  compiler::FeedbackSource feedback_source{feedback(), slot};

  const compiler::ProcessedFeedback& processed_feedback =
      broker()->GetFeedbackForPropertyAccess(
          feedback_source, compiler::AccessMode::kStore, name);

  auto build_generic_access = [this, object, &name, &feedback_source]() {
    ValueNode* context = GetContext();
    ValueNode* value = GetAccumulator();
    AddNewNode<DefineNamedOwnGeneric>({context, object, value}, name,
                                      feedback_source);
    return ReduceResult::Done();
  };
  switch (processed_feedback.kind()) {
    case compiler::ProcessedFeedback::kInsufficient:
      RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
          DeoptimizeReason::kInsufficientTypeFeedbackForGenericNamedAccess));

    case compiler::ProcessedFeedback::kNamedAccess:
      RETURN_VOID_IF_DONE(TryBuildNamedAccess(
          object, object, processed_feedback.AsNamedAccess(), feedback_source,
          compiler::AccessMode::kDefine, build_generic_access));
      break;

    default:
      break;
  }

  // Create a generic store in the fallthrough.
  RETURN_VOID_IF_ABORT(build_generic_access());
}

void MaglevGraphBuilder::VisitSetKeyedProperty() {
  // SetKeyedProperty <object> <key> <slot>
  ValueNode* object = LoadRegister(0);
  FeedbackSlot slot = GetSlotOperand(2);
  compiler::FeedbackSource feedback_source{feedback(), slot};

  const compiler::ProcessedFeedback& processed_feedback =
      broker()->GetFeedbackForPropertyAccess(
          feedback_source, compiler::AccessMode::kStore, std::nullopt);

  auto build_generic_access = [this, object, &feedback_source]() {
    ValueNode* key = LoadRegister(1);
    ValueNode* context = GetContext();
    ValueNode* value = GetAccumulator();
    AddNewNode<SetKeyedGeneric>({context, object, key, value}, feedback_source);
    return ReduceResult::Done();
  };

  switch (processed_feedback.kind()) {
    case compiler::ProcessedFeedback::kInsufficient:
      RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
          DeoptimizeReason::kInsufficientTypeFeedbackForGenericKeyedAccess));

    case compiler::ProcessedFeedback::kElementAccess: {
      // Get the key without conversion. TryBuildElementAccess will try to pick
      // the best representation.
      ValueNode* index =
          current_interpreter_frame_.get(iterator_.GetRegisterOperand(1));
      RETURN_VOID_IF_DONE(TryBuildElementAccess(
          object, index, processed_feedback.AsElementAccess(), feedback_source,
          build_generic_access));
    } break;

    default:
      break;
  }

  // Create a generic store in the fallthrough.
  RETURN_VOID_IF_ABORT(build_generic_access());
}

void MaglevGraphBuilder::VisitDefineKeyedOwnProperty() {
  // DefineKeyedOwnProperty <object> <key> <flags> <slot>
  ValueNode* object = LoadRegister(0);
  ValueNode* key = LoadRegister(1);
  ValueNode* flags = GetSmiConstant(GetFlag8Operand(2));
  FeedbackSlot slot = GetSlotOperand(3);
  compiler::FeedbackSource feedback_source{feedback(), slot};

  // TODO(victorgomes): Add monomorphic fast path.

  // Create a generic store in the fallthrough.
  ValueNode* context = GetContext();
  ValueNode* value = GetAccumulator();
  AddNewNode<DefineKeyedOwnGeneric>({context, object, key, value, flags},
                                    feedback_source);
}

void MaglevGraphBuilder::VisitStaInArrayLiteral() {
  // StaInArrayLiteral <object> <index> <slot>
  ValueNode* object = LoadRegister(0);
  ValueNode* index = LoadRegister(1);
  FeedbackSlot slot = GetSlotOperand(2);
  compiler::FeedbackSource feedback_source{feedback(), slot};

  const compiler::ProcessedFeedback& processed_feedback =
      broker()->GetFeedbackForPropertyAccess(
          feedback_source, compiler::AccessMode::kStoreInLiteral, std::nullopt);

  auto build_generic_access = [this, object, index, &feedback_source]() {
    ValueNode* context = GetContext();
    ValueNode* value = GetAccumulator();
    AddNewNode<StoreInArrayLiteralGeneric>({context, object, index, value},
                                           feedback_source);
    return ReduceResult::Done();
  };

  switch (processed_feedback.kind()) {
    case compiler::ProcessedFeedback::kInsufficient:
      RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
          DeoptimizeReason::kInsufficientTypeFeedbackForGenericKeyedAccess));

    case compiler::ProcessedFeedback::kElementAccess: {
      RETURN_VOID_IF_DONE(TryBuildElementAccess(
          object, index, processed_feedback.AsElementAccess(), feedback_source,
          build_generic_access));
      break;
    }

    default:
      break;
  }

  // Create a generic store in the fallthrough.
  RETURN_VOID_IF_ABORT(build_generic_access());
}

void MaglevGraphBuilder::VisitDefineKeyedOwnPropertyInLiteral() {
  ValueNode* object = LoadRegister(0);
  ValueNode* name = LoadRegister(1);
  ValueNode* value = GetAccumulator();
  ValueNode* flags = GetSmiConstant(GetFlag8Operand(2));
  ValueNode* slot = GetTaggedIndexConstant(GetSlotOperand(3).ToInt());
  ValueNode* feedback_vector = GetConstant(feedback());
  CHECK(BuildCallRuntime(Runtime::kDefineKeyedOwnPropertyInLiteral,
                         {object, name, value, flags, feedback_vector, slot})
            .IsDone());
}

void MaglevGraphBuilder::VisitAdd() { VisitBinaryOperation<Operation::kAdd>(); }
void MaglevGraphBuilder::VisitSub() {
  VisitBinaryOperation<Operation::kSubtract>();
}
void MaglevGraphBuilder::VisitMul() {
  VisitBinaryOperation<Operation::kMultiply>();
}
void MaglevGraphBuilder::VisitDiv() {
  VisitBinaryOperation<Operation::kDivide>();
}
void MaglevGraphBuilder::VisitMod() {
  VisitBinaryOperation<Operation::kModulus>();
}
void MaglevGraphBuilder::VisitExp() {
  VisitBinaryOperation<Operation::kExponentiate>();
}
void MaglevGraphBuilder::VisitBitwiseOr() {
  VisitBinaryOperation<Operation::kBitwiseOr>();
}
void MaglevGraphBuilder::VisitBitwiseXor() {
  VisitBinaryOperation<Operation::kBitwiseXor>();
}
void MaglevGraphBuilder::VisitBitwiseAnd() {
  VisitBinaryOperation<Operation::kBitwiseAnd>();
}
void MaglevGraphBuilder::VisitShiftLeft() {
  VisitBinaryOperation<Operation::kShiftLeft>();
}
void MaglevGraphBuilder::VisitShiftRight() {
  VisitBinaryOperation<Operation::kShiftRight>();
}
void MaglevGraphBuilder::VisitShiftRightLogical() {
  VisitBinaryOperation<Operation::kShiftRightLogical>();
}

void MaglevGraphBuilder::VisitAddSmi() {
  VisitBinarySmiOperation<Operation::kAdd>();
}
void MaglevGraphBuilder::VisitSubSmi() {
  VisitBinarySmiOperation<Operation::kSubtract>();
}
void MaglevGraphBuilder::VisitMulSmi() {
  VisitBinarySmiOperation<Operation::kMultiply>();
}
void MaglevGraphBuilder::VisitDivSmi() {
  VisitBinarySmiOperation<Operation::kDivide>();
}
void MaglevGraphBuilder::VisitModSmi() {
  VisitBinarySmiOperation<Operation::kModulus>();
}
void MaglevGraphBuilder::VisitExpSmi() {
  VisitBinarySmiOperation<Operation::kExponentiate>();
}
void MaglevGraphBuilder::VisitBitwiseOrSmi() {
  VisitBinarySmiOperation<Operation::kBitwiseOr>();
}
void MaglevGraphBuilder::VisitBitwiseXorSmi() {
  VisitBinarySmiOperation<Operation::kBitwiseXor>();
}
void MaglevGraphBuilder::VisitBitwiseAndSmi() {
  VisitBinarySmiOperation<Operation::kBitwiseAnd>();
}
void MaglevGraphBuilder::VisitShiftLeftSmi() {
  VisitBinarySmiOperation<Operation::kShiftLeft>();
}
void MaglevGraphBuilder::VisitShiftRightSmi() {
  VisitBinarySmiOperation<Operation::kShiftRight>();
}
void MaglevGraphBuilder::VisitShiftRightLogicalSmi() {
  VisitBinarySmiOperation<Operation::kShiftRightLogical>();
}

void MaglevGraphBuilder::VisitInc() {
  VisitUnaryOperation<Operation::kIncrement>();
}
void MaglevGraphBuilder::VisitDec() {
  VisitUnaryOperation<Operation::kDecrement>();
}
void MaglevGraphBuilder::VisitNegate() {
  VisitUnaryOperation<Operation::kNegate>();
}
void MaglevGraphBuilder::VisitBitwiseNot() {
  VisitUnaryOperation<Operation::kBitwiseNot>();
}

void MaglevGraphBuilder::VisitToBooleanLogicalNot() {
  SetAccumulator(BuildToBoolean</* flip */ true>(GetAccumulator()));
}

ValueNode* MaglevGraphBuilder::BuildLogicalNot(ValueNode* value) {
  // TODO(victorgomes): Use NodeInfo to add more type optimizations here.
  switch (value->opcode()) {
#define CASE(Name)                                         \
  case Opcode::k##Name: {                                  \
    return GetBooleanConstant(                             \
        !value->Cast<Name>()->ToBoolean(local_isolate())); \
  }
    CONSTANT_VALUE_NODE_LIST(CASE)
#undef CASE
    default:
      return AddNewNode<LogicalNot>({value});
  }
}

void MaglevGraphBuilder::VisitLogicalNot() {
  // Invariant: accumulator must already be a boolean value.
  SetAccumulator(BuildLogicalNot(GetAccumulator()));
}

void MaglevGraphBuilder::VisitTypeOf() {
  ValueNode* value = GetAccumulator();
  PROCESS_AND_RETURN_IF_DONE(TryReduceTypeOf(value), SetAccumulator);

  FeedbackNexus nexus = FeedbackNexusForOperand(0);
  TypeOfFeedback::Result feedback = nexus.GetTypeOfFeedback();
  switch (feedback) {
    case TypeOfFeedback::kNone:
      RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
          DeoptimizeReason::kInsufficientTypeFeedbackForTypeOf));
    case TypeOfFeedback::kNumber:
      BuildCheckNumber(value);
      SetAccumulator(GetRootConstant(RootIndex::knumber_string));
      return;
    case TypeOfFeedback::kString:
      BuildCheckString(value);
      SetAccumulator(GetRootConstant(RootIndex::kstring_string));
      return;
    case TypeOfFeedback::kFunction:
      AddNewNode<CheckDetectableCallable>({value},
                                          GetCheckType(GetType(value)));
      EnsureType(value, NodeType::kCallable);
      SetAccumulator(GetRootConstant(RootIndex::kfunction_string));
      return;
    default:
      break;
  }

  SetAccumulator(BuildCallBuiltin<Builtin::kTypeof>({GetTaggedValue(value)}));
}

void MaglevGraphBuilder::VisitDeletePropertyStrict() {
  ValueNode* object = LoadRegister(0);
  ValueNode* key = GetAccumulator();
  ValueNode* context = GetContext();
  SetAccumulator(AddNewNode<DeleteProperty>({context, object, key},
                                            LanguageMode::kStrict));
}

void MaglevGraphBuilder::VisitDeletePropertySloppy() {
  ValueNode* object = LoadRegister(0);
  ValueNode* key = GetAccumulator();
  ValueNode* context = GetContext();
  SetAccumulator(AddNewNode<DeleteProperty>({context, object, key},
                                            LanguageMode::kSloppy));
}

void MaglevGraphBuilder::VisitGetSuperConstructor() {
  ValueNode* active_function = GetAccumulator();
  // TODO(victorgomes): Maybe BuildLoadTaggedField should support constants
  // instead.
  if (compiler::OptionalHeapObjectRef constant =
          TryGetConstant(active_function)) {
    compiler::MapRef map = constant->map(broker());
    if (map.is_stable()) {
      broker()->dependencies()->DependOnStableMap(map);
      ValueNode* map_proto = GetConstant(map.prototype(broker()));
      StoreRegister(iterator_.GetRegisterOperand(0), map_proto);
      return;
    }
  }
  ValueNode* map =
      BuildLoadTaggedField(active_function, HeapObject::kMapOffset);
  ValueNode* map_proto = BuildLoadTaggedField(map, Map::kPrototypeOffset);
  StoreRegister(iterator_.GetRegisterOperand(0), map_proto);
}

bool MaglevGraphBuilder::HasValidInitialMap(
    compiler::JSFunctionRef new_target, compiler::JSFunctionRef constructor) {
  if (!new_target.map(broker()).has_prototype_slot()) return false;
  if (!new_target.has_initial_map(broker())) return false;
  compiler::MapRef initial_map = new_target.initial_map(broker());
  return initial_map.GetConstructor(broker()).equals(constructor);
}

bool MaglevGraphBuilder::TryBuildFindNonDefaultConstructorOrConstruct(
    ValueNode* this_function, ValueNode* new_target,
    std::pair<interpreter::Register, interpreter::Register> result) {
  // See also:
  // JSNativeContextSpecialization::ReduceJSFindNonDefaultConstructorOrConstruct

  compiler::OptionalHeapObjectRef maybe_constant =
      TryGetConstant(this_function);
  if (!maybe_constant) return false;

  compiler::MapRef function_map = maybe_constant->map(broker());
  compiler::HeapObjectRef current = function_map.prototype(broker());

  // TODO(v8:13091): Don't produce incomplete stack traces when debug is active.
  // We already deopt when a breakpoint is set. But it would be even nicer to
  // avoid producting incomplete stack traces when when debug is active, even if
  // there are no breakpoints - then a user inspecting stack traces via Dev
  // Tools would always see the full stack trace.

  while (true) {
    if (!current.IsJSFunction()) return false;
    compiler::JSFunctionRef current_function = current.AsJSFunction();

    // If there are class fields, bail out. TODO(v8:13091): Handle them here.
    if (current_function.shared(broker())
            .requires_instance_members_initializer()) {
      return false;
    }

    // If there are private methods, bail out. TODO(v8:13091): Handle them here.
    if (current_function.context(broker())
            .scope_info(broker())
            .ClassScopeHasPrivateBrand()) {
      return false;
    }

    FunctionKind kind = current_function.shared(broker()).kind();
    if (kind != FunctionKind::kDefaultDerivedConstructor) {
      // The hierarchy walk will end here; this is the last change to bail out
      // before creating new nodes.
      if (!broker()->dependencies()->DependOnArrayIteratorProtector()) {
        return false;
      }

      compiler::OptionalHeapObjectRef new_target_function =
          TryGetConstant(new_target);
      if (kind == FunctionKind::kDefaultBaseConstructor) {
        // Store the result register first, so that a lazy deopt in
        // `FastNewObject` writes `true` to this register.
        StoreRegister(result.first, GetBooleanConstant(true));

        ValueNode* object;
        if (new_target_function && new_target_function->IsJSFunction() &&
            HasValidInitialMap(new_target_function->AsJSFunction(),
                               current_function)) {
          object = BuildInlinedAllocation(
              CreateJSConstructor(new_target_function->AsJSFunction()),
              AllocationType::kYoung);
          ClearCurrentAllocationBlock();
        } else {
          object = BuildCallBuiltin<Builtin::kFastNewObject>(
              {GetConstant(current_function), GetTaggedValue(new_target)});
          // We've already stored "true" into result.first, so a deopt here just
          // has to store result.second. Also mark result.first as being used,
          // since the lazy deopt frame won't have marked it since it used to be
          // a result register.
          AddDeoptUse(current_interpreter_frame_.get(result.first));
          object->lazy_deopt_info()->UpdateResultLocation(result.second, 1);
        }
        StoreRegister(result.second, object);
      } else {
        StoreRegister(result.first, GetBooleanConstant(false));
        StoreRegister(result.second, GetConstant(current));
      }

      broker()->dependencies()->DependOnStablePrototypeChain(
          function_map, WhereToStart::kStartAtReceiver, current_function);
      return true;
    }

    // Keep walking up the class tree.
    current = current_function.map(broker()).prototype(broker());
  }
}

void MaglevGraphBuilder::VisitFindNonDefaultConstructorOrConstruct() {
  ValueNode* this_function = LoadRegister(0);
  ValueNode* new_target = LoadRegister(1);

  auto register_pair = iterator_.GetRegisterPairOperand(2);

  if (TryBuildFindNonDefaultConstructorOrConstruct(this_function, new_target,
                                                   register_pair)) {
    return;
  }

  CallBuiltin* result =
      BuildCallBuiltin<Builtin::kFindNonDefaultConstructorOrConstruct>(
          {GetTaggedValue(this_function), GetTaggedValue(new_target)});
  StoreRegisterPair(register_pair, result);
}

namespace {
void ForceEscapeIfAllocation(ValueNode* value) {
  if (InlinedAllocation* alloc = value->TryCast<InlinedAllocation>()) {
    alloc->ForceEscaping();
  }
}
}  // namespace

ReduceResult MaglevGraphBuilder::BuildInlined(ValueNode* context,
                                              ValueNode* function,
                                              ValueNode* new_target,
                                              const CallArguments& args) {
  DCHECK(is_inline());

  // Manually create the prologue of the inner function graph, so that we
  // can manually set up the arguments.
  DCHECK_NOT_NULL(current_block_);

  // Set receiver.
  ValueNode* receiver =
      GetConvertReceiver(compilation_unit_->shared_function_info(), args);
  SetArgument(0, receiver);

  // The inlined function could call a builtin that iterates the frame, the
  // receiver needs to have been materialized.
  // TODO(victorgomes): Can we relax this requirement? Maybe we can allocate the
  // object lazily? This is also only required if the inlined function is not a
  // leaf (ie. it calls other functions).
  ForceEscapeIfAllocation(receiver);

  // Set remaining arguments.
  RootConstant* undefined_constant =
      GetRootConstant(RootIndex::kUndefinedValue);
  int arg_count = static_cast<int>(args.count());
  int formal_parameter_count = compilation_unit_->parameter_count() - 1;
  for (int i = 0; i < formal_parameter_count; i++) {
    ValueNode* arg_value = args[i];
    if (arg_value == nullptr) arg_value = undefined_constant;
    SetArgument(i + 1, arg_value);
  }

  // Save all arguments if we have a mismatch between arguments count and
  // parameter count.
  inlined_arguments_ = zone()->AllocateVector<ValueNode*>(arg_count + 1);
  inlined_arguments_[0] = receiver;
  for (int i = 0; i < arg_count; i++) {
    inlined_arguments_[i + 1] = args[i];
  }

  inlined_new_target_ = new_target;

  BuildRegisterFrameInitialization(context, function, new_target);
  BuildMergeStates();
  EndPrologue();
  in_prologue_ = false;

  // Build the inlined function body.
  BuildBody();

  // All returns in the inlined body jump to a merge point one past the bytecode
  // length (i.e. at offset bytecode.length()). If there isn't one already,
  // create a block at this fake offset and have it jump out of the inlined
  // function, into a new block that we create which resumes execution of the
  // outer function.
  if (!current_block_) {
    // If we don't have a merge state at the inline_exit_offset, then there is
    // no control flow that reaches the end of the inlined function, either
    // because of infinite loops or deopts
    if (merge_states_[inline_exit_offset()] == nullptr) {
      return ReduceResult::DoneWithAbort();
    }

    ProcessMergePoint(inline_exit_offset(), /*preserve_kna*/ false);
    StartNewBlock(inline_exit_offset(), /*predecessor*/ nullptr);
  }

  // Pull the returned accumulator value out of the inlined function's final
  // merged return state.
  return current_interpreter_frame_.accumulator();
}

#define TRACE_INLINING(...)                       \
  do {                                            \
    if (v8_flags.trace_maglev_inlining)           \
      StdoutStream{} << __VA_ARGS__ << std::endl; \
  } while (false)

#define TRACE_CANNOT_INLINE(...) \
  TRACE_INLINING("  cannot inline " << shared << ": " << __VA_ARGS__)

bool MaglevGraphBuilder::ShouldInlineCall(
    compiler::SharedFunctionInfoRef shared,
    compiler::OptionalFeedbackVectorRef feedback_vector, float call_frequency) {
  if (graph()->total_inlined_bytecode_size() >
      v8_flags.max_maglev_inlined_bytecode_size_cumulative) {
    compilation_unit_->info()->set_could_not_inline_all_candidates();
    TRACE_CANNOT_INLINE("maximum inlined bytecode size");
    return false;
  }
  if (!feedback_vector) {
    // TODO(verwaest): Soft deopt instead?
    TRACE_CANNOT_INLINE("it has not been compiled/run with feedback yet");
    return false;
  }
  // TODO(olivf): This is a temporary stopgap to prevent infinite recursion when
  // inlining, because we currently excempt small functions from some of the
  // negative heuristics. We should refactor these heuristics and make sure they
  // make sense in the presence of (mutually) recursive inlining. Please do
  // *not* return true before this check.
  if (inlining_depth() > v8_flags.max_maglev_hard_inline_depth) {
    TRACE_CANNOT_INLINE("inlining depth ("
                        << inlining_depth() << ") >= hard-max-depth ("
                        << v8_flags.max_maglev_hard_inline_depth << ")");
    return false;
  }
  if (compilation_unit_->shared_function_info().equals(shared)) {
    TRACE_CANNOT_INLINE("direct recursion");
    return false;
  }
  SharedFunctionInfo::Inlineability inlineability =
      shared.GetInlineability(broker());
  if (inlineability != SharedFunctionInfo::Inlineability::kIsInlineable) {
    TRACE_CANNOT_INLINE(inlineability);
    return false;
  }
  // TODO(victorgomes): Support NewTarget/RegisterInput in inlined functions.
  compiler::BytecodeArrayRef bytecode = shared.GetBytecodeArray(broker());
  if (bytecode.incoming_new_target_or_generator_register().is_valid()) {
    TRACE_CANNOT_INLINE("use unsupported NewTargetOrGenerator register");
    return false;
  }
  if (call_frequency < v8_flags.min_maglev_inlining_frequency) {
    TRACE_CANNOT_INLINE("call frequency ("
                        << call_frequency << ") < minimum threshold ("
                        << v8_flags.min_maglev_inlining_frequency << ")");
    return false;
  }
  if (bytecode.length() < v8_flags.max_maglev_inlined_bytecode_size_small) {
    TRACE_INLINING("  inlining "
                   << shared
                   << ": small function, skipping max-size and max-depth");
    return true;
  }
  if (bytecode.length() > v8_flags.max_maglev_inlined_bytecode_size) {
    TRACE_CANNOT_INLINE("big function, size ("
                        << bytecode.length() << ") >= max-size ("
                        << v8_flags.max_maglev_inlined_bytecode_size << ")");
    return false;
  }
  if (inlining_depth() > v8_flags.max_maglev_inline_depth) {
    TRACE_CANNOT_INLINE("inlining depth ("
                        << inlining_depth() << ") >= max-depth ("
                        << v8_flags.max_maglev_inline_depth << ")");
    return false;
  }
  TRACE_INLINING("  inlining " << shared);
  if (v8_flags.trace_maglev_inlining_verbose) {
    BytecodeArray::Disassemble(bytecode.object(), std::cout);
    i::Print(*feedback_vector->object(), std::cout);
  }
  graph()->add_inlined_bytecode_size(bytecode.length());
  return true;
}

ReduceResult MaglevGraphBuilder::TryBuildInlinedCall(
    ValueNode* context, ValueNode* function, ValueNode* new_target,
    compiler::SharedFunctionInfoRef shared,
    compiler::OptionalFeedbackVectorRef feedback_vector, CallArguments& args,
    const compiler::FeedbackSource& feedback_source) {
  DCHECK_EQ(args.mode(), CallArguments::kDefault);
  float feedback_frequency = 0.0f;
  if (feedback_source.IsValid()) {
    compiler::ProcessedFeedback const& feedback =
        broker()->GetFeedbackForCall(feedback_source);
    feedback_frequency =
        feedback.IsInsufficient() ? 0.0f : feedback.AsCall().frequency();
  }
  float call_frequency = feedback_frequency * call_frequency_;
  if (!ShouldInlineCall(shared, feedback_vector, call_frequency)) {
    return ReduceResult::Fail();
  }

  compiler::BytecodeArrayRef bytecode = shared.GetBytecodeArray(broker());

  if (v8_flags.maglev_print_inlined &&
      TopLevelFunctionPassMaglevPrintFilter() &&
      (v8_flags.print_maglev_code || v8_flags.print_maglev_graph ||
       v8_flags.print_maglev_graphs)) {
    std::cout << "== Inlining " << Brief(*shared.object()) << std::endl;
    BytecodeArray::Disassemble(bytecode.object(), std::cout);
    if (v8_flags.maglev_print_feedback) {
      i::Print(*feedback_vector->object(), std::cout);
    }
  } else if (v8_flags.trace_maglev_graph_building) {
    std::cout << "== Inlining " << shared.object() << std::endl;
  }

  graph()->inlined_functions().push_back(
      OptimizedCompilationInfo::InlinedFunctionHolder(
          shared.object(), bytecode.object(), current_source_position_));
  if (feedback_vector->object()->invocation_count_before_stable(kRelaxedLoad) >
      v8_flags.invocation_count_for_early_optimization) {
    compilation_unit_->info()->set_could_not_inline_all_candidates();
  }
  int inlining_id = static_cast<int>(graph()->inlined_functions().size() - 1);

  // Create a new compilation unit and graph builder for the inlined
  // function.
  MaglevCompilationUnit* inner_unit = MaglevCompilationUnit::NewInner(
      zone(), compilation_unit_, shared, feedback_vector.value());
  MaglevGraphBuilder inner_graph_builder(
      local_isolate_, inner_unit, graph_, call_frequency,
      BytecodeOffset(iterator_.current_offset()), IsInsideLoop(), inlining_id,
      this);

  // Merge catch block state if needed.
  CatchBlockDetails catch_block = GetCurrentTryCatchBlock();
  if (catch_block.ref && catch_block.state->exception_handler_was_used()) {
    // Merge the current state into the handler state.
    catch_block.state->MergeThrow(
        GetCurrentCatchBlockGraphBuilder(), catch_block.unit,
        *current_interpreter_frame_.known_node_aspects(),
        current_interpreter_frame_.virtual_objects());
  }

  // Propagate catch block.
  inner_graph_builder.parent_catch_ = catch_block;
  inner_graph_builder.parent_catch_deopt_frame_distance_ =
      1 + (IsInsideTryBlock() ? 0 : parent_catch_deopt_frame_distance_);

  // Set the inner graph builder to build in the current block.
  inner_graph_builder.current_block_ = current_block_;

  ReduceResult result =
      inner_graph_builder.BuildInlined(context, function, new_target, args);
  if (result.IsDoneWithAbort()) {
    DCHECK_NULL(inner_graph_builder.current_block_);
    current_block_ = nullptr;
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "== Finished inlining (abort) " << shared.object()
                << std::endl;
    }
    return ReduceResult::DoneWithAbort();
  }

  // Propagate KnownNodeAspects back to the caller.
  current_interpreter_frame_.set_known_node_aspects(
      inner_graph_builder.current_interpreter_frame_.known_node_aspects());
  unobserved_context_slot_stores_ =
      inner_graph_builder.unobserved_context_slot_stores_;

  // Propagate virtual object lists back to the caller.
  current_interpreter_frame_.set_virtual_objects(
      inner_graph_builder.current_interpreter_frame_.virtual_objects());

  DCHECK(result.IsDoneWithValue());
  // Resume execution using the final block of the inner builder.
  current_block_ = inner_graph_builder.current_block_;

  if (v8_flags.trace_maglev_graph_building) {
    std::cout << "== Finished inlining " << shared.object() << std::endl;
  }
  return result;
}

namespace {

bool CanInlineArrayIteratingBuiltin(compiler::JSHeapBroker* broker,
                                    const PossibleMaps& maps,
                                    ElementsKind* kind_return) {
  DCHECK_NE(0, maps.size());
  *kind_return = maps.at(0).elements_kind();
  for (compiler::MapRef map : maps) {
    if (!map.supports_fast_array_iteration(broker) ||
        !UnionElementsKindUptoSize(kind_return, map.elements_kind())) {
      return false;
    }
  }
  return true;
}

}  // namespace

ReduceResult MaglevGraphBuilder::TryReduceArrayIsArray(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() == 0) return GetBooleanConstant(false);

  ValueNode* node = args[0];

  if (CheckType(node, NodeType::kJSArray)) {
    return GetBooleanConstant(true);
  }

  auto node_info = known_node_aspects().TryGetInfoFor(node);
  if (node_info && node_info->possible_maps_are_known()) {
    bool has_array_map = false;
    bool has_proxy_map = false;
    bool has_other_map = false;
    for (compiler::MapRef map : node_info->possible_maps()) {
      InstanceType type = map.instance_type();
      if (InstanceTypeChecker::IsJSArray(type)) {
        has_array_map = true;
      } else if (InstanceTypeChecker::IsJSProxy(type)) {
        has_proxy_map = true;
      } else {
        has_other_map = true;
      }
    }
    if ((has_array_map ^ has_other_map) && !has_proxy_map) {
      if (has_array_map) node_info->CombineType(NodeType::kJSArray);
      return GetBooleanConstant(has_array_map);
    }
  }

  // TODO(verwaest): Add a node that checks the instance type.
  return ReduceResult::Fail();
}

ReduceResult MaglevGraphBuilder::TryReduceArrayForEach(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }

  ValueNode* receiver = args.receiver();
  if (!receiver) return ReduceResult::Fail();

  if (args.count() < 1) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.forEach - not enough "
                   "arguments"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  auto node_info = known_node_aspects().TryGetInfoFor(receiver);
  if (!node_info || !node_info->possible_maps_are_known()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.forEach - receiver "
                   "map is unknown"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  ElementsKind elements_kind;
  if (!CanInlineArrayIteratingBuiltin(broker(), node_info->possible_maps(),
                                      &elements_kind)) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.forEach - doesn't "
                   "support fast array iteration or incompatible maps"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  // TODO(leszeks): May only be needed for holey elements kinds.
  if (!broker()->dependencies()->DependOnNoElementsProtector()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.forEach - invalidated "
                   "no elements protector"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  ValueNode* callback = args[0];
  if (!callback->is_tagged()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.forEach - callback is "
                   "untagged value"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  ValueNode* this_arg =
      args.count() > 1 ? args[1] : GetRootConstant(RootIndex::kUndefinedValue);

  ValueNode* original_length = BuildLoadJSArrayLength(receiver);

  // Elide the callable check if the node is known callable.
  EnsureType(callback, NodeType::kCallable, [&](NodeType old_type) {
    // ThrowIfNotCallable is wrapped in a lazy_deopt_scope to make sure the
    // exception has the right call stack.
    DeoptFrameScope lazy_deopt_scope(
        this, Builtin::kArrayForEachLoopLazyDeoptContinuation, target,
        base::VectorOf<ValueNode*>({receiver, callback, this_arg,
                                    GetSmiConstant(0), original_length}));
    AddNewNode<ThrowIfNotCallable>({callback});
  });

  ValueNode* original_length_int32 = GetInt32(original_length);

  // Remember the receiver map set before entering the loop the call.
  bool receiver_maps_were_unstable = node_info->possible_maps_are_unstable();
  PossibleMaps receiver_maps_before_loop(node_info->possible_maps());

  // Create a sub graph builder with two variable (index and length)
  MaglevSubGraphBuilder sub_builder(this, 2);
  MaglevSubGraphBuilder::Variable var_index(0);
  MaglevSubGraphBuilder::Variable var_length(1);

  MaglevSubGraphBuilder::Label loop_end(&sub_builder, 1);

  // ```
  // index = 0
  // bind loop_header
  // ```
  sub_builder.set(var_index, GetSmiConstant(0));
  sub_builder.set(var_length, original_length);
  MaglevSubGraphBuilder::LoopLabel loop_header =
      sub_builder.BeginLoop({&var_index, &var_length});

  // Reset known state that is cleared by BeginLoop, but is known to be true on
  // the first iteration, and will be re-checked at the end of the loop.

  // Reset the known receiver maps if necessary.
  if (receiver_maps_were_unstable) {
    node_info->SetPossibleMaps(receiver_maps_before_loop,
                               receiver_maps_were_unstable,
                               // Node type is monotonic, no need to reset it.
                               NodeType::kUnknown, broker());
    known_node_aspects().any_map_for_any_node_is_unstable = true;
  } else {
    DCHECK_EQ(node_info->possible_maps().size(),
              receiver_maps_before_loop.size());
  }
  // Reset the cached loaded array length to the length var.
  RecordKnownProperty(receiver, broker()->length_string(),
                      sub_builder.get(var_length), false,
                      compiler::AccessMode::kLoad);

  // ```
  // if (index_int32 < length_int32)
  //   fallthrough
  // else
  //   goto end
  // ```
  Phi* index_tagged = sub_builder.get(var_index)->Cast<Phi>();
  EnsureType(index_tagged, NodeType::kSmi);
  ValueNode* index_int32 = GetInt32(index_tagged);

  sub_builder.GotoIfFalse<BranchIfInt32Compare>(
      &loop_end, {index_int32, original_length_int32}, Operation::kLessThan);

  // ```
  // next_index = index + 1
  // ```
  ValueNode* next_index_int32 = nullptr;
  {
    // Eager deopt scope for index increment overflow.
    // TODO(pthier): In practice this increment can never overflow, as the max
    // possible array length is less than int32 max value. Add a new
    // Int32Increment that asserts no overflow instead of deopting.
    DeoptFrameScope eager_deopt_scope(
        this, Builtin::kArrayForEachLoopEagerDeoptContinuation, target,
        base::VectorOf<ValueNode*>(
            {receiver, callback, this_arg, index_int32, original_length}));
    next_index_int32 = AddNewNode<Int32IncrementWithOverflow>({index_int32});
    EnsureType(next_index_int32, NodeType::kSmi);
  }
  // TODO(leszeks): Assert Smi.

  // ```
  // element = array.elements[index]
  // ```
  ValueNode* elements = BuildLoadElements(receiver);
  ValueNode* element;
  if (IsDoubleElementsKind(elements_kind)) {
    element = BuildLoadFixedDoubleArrayElement(elements, index_int32);
  } else {
    element = BuildLoadFixedArrayElement(elements, index_int32);
  }

  std::optional<MaglevSubGraphBuilder::Label> skip_call;
  if (IsHoleyElementsKind(elements_kind)) {
    // ```
    // if (element is hole) goto skip_call
    // ```
    skip_call.emplace(
        &sub_builder, 2,
        std::initializer_list<MaglevSubGraphBuilder::Variable*>{&var_length});
    if (elements_kind == HOLEY_DOUBLE_ELEMENTS) {
      sub_builder.GotoIfTrue<BranchIfFloat64IsHole>(&*skip_call, {element});
    } else {
      sub_builder.GotoIfTrue<BranchIfRootConstant>(&*skip_call, {element},
                                                   RootIndex::kTheHoleValue);
    }
  }

  // ```
  // callback(this_arg, element, array)
  // ```
  ReduceResult result;
  {
    DeoptFrameScope lazy_deopt_scope(
        this, Builtin::kArrayForEachLoopLazyDeoptContinuation, target,
        base::VectorOf<ValueNode*>(
            {receiver, callback, this_arg, next_index_int32, original_length}));

    CallArguments call_args =
        args.count() < 2
            ? CallArguments(ConvertReceiverMode::kNullOrUndefined,
                            {element, index_tagged, receiver})
            : CallArguments(ConvertReceiverMode::kAny,
                            {this_arg, element, index_tagged, receiver});

    SaveCallSpeculationScope saved(this);
    result = ReduceCall(callback, call_args, saved.value());
  }

  // ```
  // index = next_index
  // jump loop_header
  // ```
  DCHECK_IMPLIES(result.IsDoneWithAbort(), current_block_ == nullptr);

  // No need to finish the loop if this code is unreachable.
  if (!result.IsDoneWithAbort()) {
    // If any of the receiver's maps were unstable maps, we have to re-check the
    // maps on each iteration, in case the callback changed them. That said, we
    // know that the maps are valid on the first iteration, so we can rotate the
    // check to _after_ the callback, and then elide it if the receiver maps are
    // still known to be valid (i.e. the known maps after the call are contained
    // inside the known maps before the call).
    bool recheck_maps_after_call = receiver_maps_were_unstable;
    if (recheck_maps_after_call) {
      // No need to recheck maps if there are known maps...
      if (auto receiver_info_after_call =
              known_node_aspects().TryGetInfoFor(receiver)) {
        // ... and those known maps are equal to, or a subset of, the maps
        // before the call.
        if (receiver_info_after_call &&
            receiver_info_after_call->possible_maps_are_known()) {
          recheck_maps_after_call = !receiver_maps_before_loop.contains(
              receiver_info_after_call->possible_maps());
        }
      }
    }

    // Make sure to finish the loop if we eager deopt in the map check or index
    // check.
    DeoptFrameScope eager_deopt_scope(
        this, Builtin::kArrayForEachLoopEagerDeoptContinuation, target,
        base::VectorOf<ValueNode*>(
            {receiver, callback, this_arg, next_index_int32, original_length}));

    if (recheck_maps_after_call) {
      // Build the CheckMap manually, since we're doing it with already known
      // maps rather than feedback, and we don't need to update known node
      // aspects or types since we're at the end of the loop anyway.
      bool emit_check_with_migration = std::any_of(
          receiver_maps_before_loop.begin(), receiver_maps_before_loop.end(),
          [](compiler::MapRef map) { return map.is_migration_target(); });
      if (emit_check_with_migration) {
        AddNewNode<CheckMapsWithMigration>({receiver},
                                           receiver_maps_before_loop,
                                           CheckType::kOmitHeapObjectCheck);
      } else {
        AddNewNode<CheckMaps>({receiver}, receiver_maps_before_loop,
                              CheckType::kOmitHeapObjectCheck);
      }
    }

    // Check if the index is still in bounds, in case the callback changed the
    // length.
    ValueNode* current_length = BuildLoadJSArrayLength(receiver);
    sub_builder.set(var_length, current_length);

    // Reference compare the loaded length against the original length. If this
    // is the same value node, then we didn't have any side effects and didn't
    // clear the cached length.
    if (current_length != original_length) {
      RETURN_IF_ABORT(
          TryBuildCheckInt32Condition(original_length_int32, current_length,
                                      AssertCondition::kUnsignedLessThanEqual,
                                      DeoptimizeReason::kArrayLengthChanged));
    }
  }

  if (skip_call.has_value()) {
    sub_builder.GotoOrTrim(&*skip_call);
    sub_builder.Bind(&*skip_call);
  }

  sub_builder.set(var_index, next_index_int32);
  sub_builder.EndLoop(&loop_header);

  // ```
  // bind end
  // ```
  sub_builder.Bind(&loop_end);

  return GetRootConstant(RootIndex::kUndefinedValue);
}

ReduceResult MaglevGraphBuilder::TryReduceArrayIteratorPrototypeNext(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }

  ValueNode* receiver = args.receiver();
  if (!receiver) return ReduceResult::Fail();

  if (!receiver->Is<InlinedAllocation>()) return ReduceResult::Fail();
  VirtualObject* iterator = receiver->Cast<InlinedAllocation>()->object();
  if (!iterator->map().IsJSArrayIteratorMap()) {
    FAIL("iterator is not a JS array iterator object");
  }

  ValueNode* iterated_object =
      iterator->get(JSArrayIterator::kIteratedObjectOffset);
  ElementsKind elements_kind;
  base::SmallVector<compiler::MapRef, 4> maps;
  if (iterated_object->Is<InlinedAllocation>()) {
    VirtualObject* array = iterated_object->Cast<InlinedAllocation>()->object();
    // TODO(victorgomes): Remove this once we track changes in the inlined
    // allocated object.
    if (iterated_object->Cast<InlinedAllocation>()->IsEscaping()) {
      FAIL("allocation is escaping, map could have been changed");
    }
    // TODO(victorgomes): This effectively disable the optimization for `for-of`
    // loops. We need to figure it out a way to re-enable this.
    if (IsInsideLoop()) {
      FAIL("we're inside a loop, iterated object map could change");
    }
    auto map = array->map();
    if (!map.supports_fast_array_iteration(broker())) {
      FAIL("no fast array iteration support");
    }
    elements_kind = map.elements_kind();
    maps.push_back(map);
  } else {
    auto node_info = known_node_aspects().TryGetInfoFor(iterated_object);
    if (!node_info || !node_info->possible_maps_are_known()) {
      FAIL("iterated object is unknown");
    }
    if (!CanInlineArrayIteratingBuiltin(broker(), node_info->possible_maps(),
                                        &elements_kind)) {
      FAIL("no fast array iteration support or incompatible maps");
    }
    for (auto map : node_info->possible_maps()) {
      maps.push_back(map);
    }
  }

  // TODO(victorgomes): Support typed arrays.
  if (IsTypedArrayElementsKind(elements_kind)) {
    FAIL("no typed arrays support");
  }

  if (IsHoleyElementsKind(elements_kind) &&
      !broker()->dependencies()->DependOnNoElementsProtector()) {
    FAIL("no elements protector");
  }

  // Load the [[NextIndex]] from the {iterator}.
  // We can assume index and length fit in Uint32.
  ValueNode* index =
      BuildLoadTaggedField(receiver, JSArrayIterator::kNextIndexOffset);
  ValueNode* uint32_index;
  GET_VALUE_OR_ABORT(uint32_index, GetUint32ElementIndex(index));
  ValueNode* uint32_length;
  GET_VALUE_OR_ABORT(uint32_length,
                     GetUint32ElementIndex(BuildLoadJSArrayLength(
                         iterated_object, IsFastElementsKind(elements_kind)
                                              ? NodeType::kSmi
                                              : NodeType::kNumber)));

  // Check next index is below length
  MaglevSubGraphBuilder subgraph(this, 2);
  MaglevSubGraphBuilder::Variable is_done(0);
  MaglevSubGraphBuilder::Variable ret_value(1)
```