Response:
Let's break down the thought process for analyzing this code snippet and fulfilling the request.

1. **Understand the Core Task:** The request asks for an analysis of a specific V8 source file (`maglev-graph-builder.cc`). It specifically wants to know the file's functionality, its relationship to JavaScript, examples, code logic inference, common errors, and a summary of its purpose within the provided context (part 7 of 18).

2. **Initial Code Scan and Keyword Identification:** Quickly read through the code, looking for recurring keywords and patterns. Keywords like `Build`, `Load`, `Store`, `FixedArray`, `JSArray`, `Property`, `Map`, `Constant`, `Check`, `ReduceResult`, and the various node types (e.g., `StoreFixedArrayElementNoWriteBarrier`) stand out. These keywords suggest the code is involved in creating and manipulating an intermediate representation (the "graph") for JavaScript operations, likely within the Maglev compiler.

3. **Deduce Primary Functionality:** Based on the keywords, the file's main function seems to be building a graph of operations. It handles loading and storing elements in arrays (both fixed and JS arrays), managing object properties (including constants and accessors), and dealing with object maps and their stability. The presence of `ReduceResult` hints at optimization attempts and the possibility of failing to optimize certain operations.

4. **Identify JavaScript Relationships:**  The code directly deals with JavaScript concepts like arrays, objects, properties, prototypes, and string lengths. The examples requested should demonstrate how these JavaScript concepts are translated into the Maglev graph. Think about common array and object operations in JavaScript.

5. **Code Logic Inference (Specific Examples):**
    * **`BuildStoreFixedArrayElement`:**  The code checks for `CanTrackObjectChanges`. This implies an optimization where, if the object's structure is known, a less expensive store operation (`NoWriteBarrier`) can be used. Otherwise, a more general store (`WithWriteBarrier`) is necessary. This suggests a performance optimization based on object tracking.
    * **`BuildLoadFixedDoubleArrayElement`:** This has two versions: one with a constant index and one with a variable index. The constant index version attempts to directly retrieve the value if the array and index are within bounds and tracked. Otherwise, it falls back to a more general load. This shows an optimization for constant access. The handling of negative or out-of-bounds indices returning `TheHoleValue` connects to JavaScript's behavior with sparse arrays or invalid accesses.
    * **`CanTreatHoleAsUndefined`:** This function checks prototype chains, specifically for `Array.prototype` or `Object.prototype`. This relates to how JavaScript treats missing array elements (holes) in certain operations, sometimes converting them to `undefined`.
    * **`TryBuildPropertyLoad` and `TryBuildPropertyStore`:** These functions handle different property access scenarios (data fields, accessors, constants, etc.). The switch statement based on `access_info.kind()` indicates different optimization paths depending on the property type and accessibility.

6. **Consider Common Programming Errors:** Think about mistakes JavaScript developers make related to the functionality seen in the code:
    * Accessing array elements out of bounds.
    * Attempting to store values in read-only properties (like the `length` of an array).
    * Incorrectly assuming object structure for optimization purposes (leading to deoptimization).
    * Type errors when storing values in typed arrays.

7. **Structure the Output:**  Organize the findings according to the request's categories:
    * **Functionality:** Provide a high-level summary of the file's purpose.
    * **Torque:** Check the filename extension.
    * **JavaScript Relationship:** Explain how the code relates to JavaScript features.
    * **JavaScript Examples:** Provide concrete JavaScript code snippets that correspond to the Maglev graph building operations.
    * **Code Logic Inference:** Explain specific code sections with assumptions about inputs and their resulting behavior.
    * **Common Programming Errors:**  Illustrate typical mistakes with JavaScript examples.
    * **Summary:** Condense the main purpose of this specific part of the Maglev graph builder.

8. **Refine and Elaborate:** After the initial draft, review and add more details or clarify points. For example, explain *why* write barriers are needed, or what the implications of stable maps are. Ensure the JavaScript examples are clear and directly relate to the C++ code.

9. **Address the "Part 7 of 18" Context:**  The fact that this is part 7 suggests that the overall Maglev compilation process is complex and involves multiple stages. This specific part seems to be responsible for a subset of the graph building, likely focusing on array and property access. The summary should reflect this.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This just builds a graph."  **Correction:** It builds a graph *for optimization purposes*, and it makes decisions about which graph nodes to create based on the properties of the JavaScript code being compiled (e.g., object stability, constant values).
* **Initial thought:** "Just give any JavaScript example." **Correction:** The examples should be *directly relevant* to the C++ code being analyzed. If the C++ deals with `StoreFixedArrayElement`, the JS example should be a fixed array store.
* **Realization:** The `ReduceResult` type is important. It signifies that these "Build" functions can sometimes fail to optimize, leading to different execution paths. This should be mentioned in the functionality description.

By following this structured approach, combining code analysis with an understanding of JavaScript concepts and common developer errors, one can effectively analyze and explain the functionality of a complex piece of code like this.
好的，让我们来分析一下 `v8/src/maglev/maglev-graph-builder.cc` 的这段代码。

**功能归纳（基于提供的代码片段）：**

这段代码是 V8 中 Maglev 编译器的图构建器（Graph Builder）的一部分，负责构建中间表示（IR）图，用于表示 JavaScript 代码的操作。它专注于以下几个方面的功能：

1. **数组操作：**
   - 加载和存储固定数组（`FixedArray`）的元素，包括是否需要写屏障（Write Barrier）。
   - 加载和存储固定双精度浮点数数组（`FixedDoubleArray`）的元素。
   - 加载可能包含空洞（Hole）的固定双精度浮点数数组的元素，并可以选择是否将空洞转换为 `undefined`。
   - 加载 JS 数组的长度。
   - 加载固定数组的长度。

2. **属性操作：**
   - 加载对象的字段（Field），包括快速属性和常量属性。
   - 尝试优化加载常量数据字段。
   - 尝试构建属性 getter 和 setter 的调用。
   - 尝试构建属性的加载和存储操作，包括处理不同的属性访问信息（`PropertyAccessInfo`），如常量属性、数据字段、访问器属性等。
   - 处理模块导出（Module Export）的加载。
   - 处理字符串长度的加载。
   - 处理字符串包装对象（String Wrapper）的长度加载。
   - 构建存储 Map 的操作，并考虑 Map 的稳定性。
   - 构建扩展属性后备存储（Properties Backing Store）的操作。
   - 尝试构建多态属性访问（Polymorphic Property Access）。

3. **类型检查和转换：**
   - 插入类型检查节点，例如检查对象是否为字符串 (`BuildCheckString`)，数字 (`BuildCheckNumber`)，或者具有特定的 Map (`BuildCheckMaps`)。
   - 将对象转换为 `int32` 或 `uint32` 类型的索引。
   - 检查 `int32` 到 `uint32` 的转换。
   - 将浮点数转换为堆上的数字对象。

4. **内置函数调用：**
   - 构建调用内置函数（Builtin）的节点，例如 `LoadIC_Megamorphic` 和 `StoreIC_Megamorphic`，用于处理多态属性访问。

5. **常量处理：**
   - 获取常量值节点 (`GetConstant`)。
   - 获取 `undefined` 常量节点。
   - 获取浮点数常量节点。

6. **优化和代码生成辅助：**
   - 利用 `PropertyAccessInfo` 来获取属性的元数据，用于优化属性访问。
   - 尝试复用已知的属性加载结果 (`TryReuseKnownPropertyLoad`).
   - 记录已知的属性信息 (`RecordKnownProperty`).
   - 依赖管理，例如依赖稳定的 Map (`DependOnStableMap`) 和稳定的原型链 (`DependOnStablePrototypeChains`).
   - 处理 Deopt（反优化）的情况 (`EmitUnconditionalDeopt`).

**关于文件后缀和 Torque：**

如果 `v8/src/maglev/maglev-graph-builder.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码。Torque 是一种 V8 内部使用的 DSL（领域特定语言），用于编写性能关键的运行时代码。  然而，你提供的代码片段是 C++ 代码，所以当前的 `maglev-graph-builder.cc` 是 C++ 文件。 Torque 文件通常会生成对应的 C++ 代码。

**与 JavaScript 的关系及示例：**

这段代码直接对应 JavaScript 的各种操作。下面用 JavaScript 举例说明一些功能：

* **数组元素访问：**
  ```javascript
  const arr = [1, 2.5, 'hello'];
  const x = arr[0]; // 对应 BuildLoadFixedArrayElement 或 BuildLoadTaggedElement
  arr[1] = 3.14;   // 对应 BuildStoreFixedArrayElement 或 BuildStoreTaggedField
  ```

* **对象属性访问：**
  ```javascript
  const obj = { a: 10, b: 'world' };
  const val = obj.a; // 对应 TryBuildPropertyLoad 和 BuildLoadField
  obj.b = 'universe'; // 对应 TryBuildPropertyStore 和 BuildStoreField
  ```

* **数组长度访问：**
  ```javascript
  const arr = [1, 2, 3];
  const len = arr.length; // 对应 BuildLoadJSArrayLength
  ```

* **原型链上的属性访问：**
  ```javascript
  function Parent() {
    this.parentProp = 'parent';
  }
  function Child() {
    this.childProp = 'child';
  }
  Child.prototype = new Parent();
  const child = new Child();
  const p = child.parentProp; // 对应 TryBuildPropertyLoad，会查找原型链
  ```

**代码逻辑推理（假设输入与输出）：**

假设有以下 JavaScript 代码：

```javascript
function foo(arr, index, value) {
  arr[index] = value;
  return arr[index];
}
```

当 Maglev 编译 `foo` 函数时，`maglev-graph-builder.cc` 中的相关代码会被调用来构建图。

* **假设输入：**
    - `arr` 是一个 `ValueNode*`，表示输入的数组。
    - `index` 是一个 `ValueNode*`，表示数组索引。
    - `value` 是一个 `ValueNode*`，表示要存储的值。

* **代码逻辑推理和可能的输出（简化）：**
    1. **`arr[index] = value;`**:
       - `GetInt32ElementIndex(index)`:  将 `index` 转换为 `int32` 索引。
       - `BuildStoreFixedArrayElement(arr, index, value)` 或 `BuildStoreTaggedField(...)`:  根据数组的类型和属性，构建存储元素的节点。如果能确定 `arr` 是一个简单的 `FixedArray` 并且可以跟踪对象变化，可能会使用 `StoreFixedArrayElementNoWriteBarrier`。
    2. **`return arr[index];`**:
       - `GetInt32ElementIndex(index)`:  再次将 `index` 转换为 `int32` 索引。
       - `BuildLoadFixedArrayElement(arr, index)` 或 `BuildLoadTaggedField(...)`:  根据数组的类型和属性，构建加载元素的节点。

**涉及用户常见的编程错误：**

1. **数组索引越界：**
   ```javascript
   const arr = [1, 2];
   console.log(arr[5]); // 用户尝试访问越界索引
   ```
   这段代码在 `BuildLoadFixedArrayElement` 或类似的函数中，可能会生成检查索引是否越界的代码，如果越界，可能会返回 `TheHoleValue` 或触发异常/Deopt。

2. **向只读属性赋值：**
   ```javascript
   const arr = [1, 2, 3];
   arr.length = 1; // 尝试修改 length 属性
   ```
   在 `TryBuildPropertyStore` 中，如果尝试修改只读属性（例如数组的 `length` 在某些情况下），会根据 `PropertyAccessInfo` 判断并可能触发 Deopt。

3. **类型错误的数组赋值：**
   ```javascript
   const arr = [1.1, 2.2]; // 可能被优化为 FixedDoubleArray
   arr[0] = 'hello'; // 尝试存储非数字类型
   ```
   在 `BuildStoreFixedDoubleArrayElement` 中，如果数组是 `FixedDoubleArray`，并且尝试存储非数字类型，会导致类型检查失败，可能触发 Deopt。

**第 7 部分功能归纳：**

作为 Maglev 编译器图构建过程的第 7 部分，这段代码的主要功能是：

- **为 JavaScript 中常见的数组和对象属性访问操作构建底层的图节点。** 这包括加载、存储以及相关的类型检查和转换。
- **利用属性访问信息（`PropertyAccessInfo`）进行优化。** 例如，对于常量属性或稳定的对象结构，可以生成更高效的代码。
- **处理不同的数组类型和属性。**  例如，区分固定数组和 JS 数组，是否包含空洞等。
- **为后续的优化和代码生成阶段提供基础的中间表示。**  构建的图将用于进一步的分析和最终的机器码生成。

总而言之，`v8/src/maglev/maglev-graph-builder.cc` 的这段代码是 Maglev 编译器核心组件之一，负责将高层次的 JavaScript 操作转化为更低层次、更易于优化的图结构。它是实现高性能 JavaScript 执行的关键部分。

### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共18部分，请归纳一下它的功能
```

### 源代码
```cpp
de<StoreFixedArrayElementNoWriteBarrier>({elements, index, value});
  } else {
    AddNewNode<StoreFixedArrayElementWithWriteBarrier>(
        {elements, index, value});
  }
}

ValueNode* MaglevGraphBuilder::BuildLoadFixedDoubleArrayElement(
    ValueNode* elements, int index) {
  if (CanTrackObjectChanges(elements, TrackObjectMode::kLoad)) {
    VirtualObject* vobject =
        GetObjectFromAllocation(elements->Cast<InlinedAllocation>());
    compiler::FixedDoubleArrayRef elements_array = vobject->double_elements();
    if (index >= 0 && static_cast<uint32_t>(index) < elements_array.length()) {
      Float64 value = elements_array.GetFromImmutableFixedDoubleArray(index);
      return GetFloat64Constant(value.get_scalar());
    } else {
      return GetRootConstant(RootIndex::kTheHoleValue);
    }
  }
  if (index < 0 || index >= FixedArray::kMaxLength) {
    return GetRootConstant(RootIndex::kTheHoleValue);
  }
  return AddNewNode<LoadFixedDoubleArrayElement>(
      {elements, GetInt32Constant(index)});
}

ValueNode* MaglevGraphBuilder::BuildLoadFixedDoubleArrayElement(
    ValueNode* elements, ValueNode* index) {
  if (auto constant = TryGetInt32Constant(index)) {
    return BuildLoadFixedDoubleArrayElement(elements, constant.value());
  }
  return AddNewNode<LoadFixedDoubleArrayElement>({elements, index});
}

void MaglevGraphBuilder::BuildStoreFixedDoubleArrayElement(ValueNode* elements,
                                                           ValueNode* index,
                                                           ValueNode* value) {
  // TODO(victorgomes): Support storing double element to a virtual object.
  AddNewNode<StoreFixedDoubleArrayElement>({elements, index, value});
}

ValueNode* MaglevGraphBuilder::BuildLoadHoleyFixedDoubleArrayElement(
    ValueNode* elements, ValueNode* index, bool convert_hole) {
  if (convert_hole) {
    return AddNewNode<LoadHoleyFixedDoubleArrayElement>({elements, index});
  } else {
    return AddNewNode<LoadHoleyFixedDoubleArrayElementCheckedNotHole>(
        {elements, index});
  }
}

bool MaglevGraphBuilder::CanTreatHoleAsUndefined(
    base::Vector<const compiler::MapRef> const& receiver_maps) {
  // Check if all {receiver_maps} have one of the initial Array.prototype
  // or Object.prototype objects as their prototype (in any of the current
  // native contexts, as the global Array protector works isolate-wide).
  for (compiler::MapRef receiver_map : receiver_maps) {
    compiler::ObjectRef receiver_prototype = receiver_map.prototype(broker());
    if (!receiver_prototype.IsJSObject() ||
        !broker()->IsArrayOrObjectPrototype(receiver_prototype.AsJSObject())) {
      return false;
    }
  }

  // Check if the array prototype chain is intact.
  return broker()->dependencies()->DependOnNoElementsProtector();
}

compiler::OptionalObjectRef
MaglevGraphBuilder::TryFoldLoadDictPrototypeConstant(
    compiler::PropertyAccessInfo const& access_info) {
  DCHECK(V8_DICT_PROPERTY_CONST_TRACKING_BOOL);
  DCHECK(access_info.IsDictionaryProtoDataConstant());
  DCHECK(access_info.holder().has_value());

  compiler::OptionalObjectRef constant =
      access_info.holder()->GetOwnDictionaryProperty(
          broker(), access_info.dictionary_index(), broker()->dependencies());
  if (!constant.has_value()) return {};

  for (compiler::MapRef map : access_info.lookup_start_object_maps()) {
    DirectHandle<Map> map_handle = map.object();
    // Non-JSReceivers that passed AccessInfoFactory::ComputePropertyAccessInfo
    // must have different lookup start map.
    if (!IsJSReceiverMap(*map_handle)) {
      // Perform the implicit ToObject for primitives here.
      // Implemented according to ES6 section 7.3.2 GetV (V, P).
      Tagged<JSFunction> constructor =
          Map::GetConstructorFunction(
              *map_handle, *broker()->target_native_context().object())
              .value();
      // {constructor.initial_map()} is loaded/stored with acquire-release
      // semantics for constructors.
      map = MakeRefAssumeMemoryFence(broker(), constructor->initial_map());
      DCHECK(IsJSObjectMap(*map.object()));
    }
    broker()->dependencies()->DependOnConstantInDictionaryPrototypeChain(
        map, access_info.name(), constant.value(), PropertyKind::kData);
  }

  return constant;
}

compiler::OptionalJSObjectRef MaglevGraphBuilder::TryGetConstantDataFieldHolder(
    compiler::PropertyAccessInfo const& access_info,
    ValueNode* lookup_start_object) {
  if (!access_info.IsFastDataConstant()) return {};
  if (access_info.holder().has_value()) {
    return access_info.holder();
  }
  if (compiler::OptionalHeapObjectRef c = TryGetConstant(lookup_start_object)) {
    if (c.value().IsJSObject()) {
      return c.value().AsJSObject();
    }
  }
  return {};
}

compiler::OptionalObjectRef MaglevGraphBuilder::TryFoldLoadConstantDataField(
    compiler::JSObjectRef holder,
    compiler::PropertyAccessInfo const& access_info) {
  DCHECK(!access_info.field_representation().IsDouble());
  return holder.GetOwnFastConstantDataProperty(
      broker(), access_info.field_representation(), access_info.field_index(),
      broker()->dependencies());
}

std::optional<Float64> MaglevGraphBuilder::TryFoldLoadConstantDoubleField(
    compiler::JSObjectRef holder,
    compiler::PropertyAccessInfo const& access_info) {
  DCHECK(access_info.field_representation().IsDouble());
  return holder.GetOwnFastConstantDoubleProperty(
      broker(), access_info.field_index(), broker()->dependencies());
}

ReduceResult MaglevGraphBuilder::TryBuildPropertyGetterCall(
    compiler::PropertyAccessInfo const& access_info, ValueNode* receiver,
    ValueNode* lookup_start_object) {
  compiler::ObjectRef constant = access_info.constant().value();

  if (access_info.IsDictionaryProtoAccessorConstant()) {
    // For fast mode holders we recorded dependencies in BuildPropertyLoad.
    for (const compiler::MapRef map : access_info.lookup_start_object_maps()) {
      broker()->dependencies()->DependOnConstantInDictionaryPrototypeChain(
          map, access_info.name(), constant, PropertyKind::kAccessor);
    }
  }

  // Introduce the call to the getter function.
  if (constant.IsJSFunction()) {
    ConvertReceiverMode receiver_mode =
        receiver == lookup_start_object
            ? ConvertReceiverMode::kNotNullOrUndefined
            : ConvertReceiverMode::kAny;
    CallArguments args(receiver_mode, {receiver});
    return ReduceCallForConstant(constant.AsJSFunction(), args);
  } else {
    // Disable optimizations for super ICs using API getters, so that we get
    // the correct receiver checks.
    if (receiver != lookup_start_object) {
      return ReduceResult::Fail();
    }
    compiler::FunctionTemplateInfoRef templ = constant.AsFunctionTemplateInfo();
    CallArguments args(ConvertReceiverMode::kNotNullOrUndefined, {receiver});

    return ReduceCallForApiFunction(templ, {}, access_info.api_holder(), args);
  }
}

ReduceResult MaglevGraphBuilder::TryBuildPropertySetterCall(
    compiler::PropertyAccessInfo const& access_info, ValueNode* receiver,
    ValueNode* lookup_start_object, ValueNode* value) {
  // Setting super properties shouldn't end up here.
  DCHECK_EQ(receiver, lookup_start_object);
  compiler::ObjectRef constant = access_info.constant().value();
  if (constant.IsJSFunction()) {
    CallArguments args(ConvertReceiverMode::kNotNullOrUndefined,
                       {receiver, value});
    RETURN_IF_ABORT(ReduceCallForConstant(constant.AsJSFunction(), args));
  } else {
    compiler::FunctionTemplateInfoRef templ = constant.AsFunctionTemplateInfo();
    CallArguments args(ConvertReceiverMode::kNotNullOrUndefined,
                       {receiver, value});
    RETURN_IF_ABORT(
        ReduceCallForApiFunction(templ, {}, access_info.api_holder(), args));
  }
  // Ignore the return value of the setter call.
  return ReduceResult::Done();
}

ValueNode* MaglevGraphBuilder::BuildLoadField(
    compiler::PropertyAccessInfo const& access_info,
    ValueNode* lookup_start_object, compiler::NameRef name) {
  compiler::OptionalJSObjectRef constant_holder =
      TryGetConstantDataFieldHolder(access_info, lookup_start_object);
  if (constant_holder) {
    if (access_info.field_representation().IsDouble()) {
      std::optional<Float64> constant =
          TryFoldLoadConstantDoubleField(constant_holder.value(), access_info);
      if (constant.has_value()) {
        return GetFloat64Constant(constant.value());
      }
    } else {
      compiler::OptionalObjectRef constant =
          TryFoldLoadConstantDataField(constant_holder.value(), access_info);
      if (constant.has_value()) {
        return GetConstant(constant.value());
      }
    }
  }
  // Resolve property holder.
  ValueNode* load_source;
  if (access_info.holder().has_value()) {
    load_source = GetConstant(access_info.holder().value());
  } else {
    load_source = lookup_start_object;
  }

  FieldIndex field_index = access_info.field_index();
  if (!field_index.is_inobject()) {
    // The field is in the property array, first load it from there.
    load_source =
        BuildLoadTaggedField(load_source, JSReceiver::kPropertiesOrHashOffset);
  }

  // Do the load.
  if (field_index.is_double()) {
    return AddNewNode<LoadDoubleField>({load_source}, field_index.offset());
  }
  ValueNode* value = BuildLoadTaggedField<LoadTaggedFieldForProperty>(
      load_source, field_index.offset(), name);
  // Insert stable field information if present.
  if (access_info.field_representation().IsSmi()) {
    NodeInfo* known_info = GetOrCreateInfoFor(value);
    known_info->CombineType(NodeType::kSmi);
  } else if (access_info.field_representation().IsHeapObject()) {
    NodeInfo* known_info = GetOrCreateInfoFor(value);
    if (access_info.field_map().has_value() &&
        access_info.field_map().value().is_stable()) {
      DCHECK(access_info.field_map().value().IsJSReceiverMap());
      auto map = access_info.field_map().value();
      known_info->SetPossibleMaps(PossibleMaps{map}, false,
                                  StaticTypeForMap(map, broker()), broker());
      broker()->dependencies()->DependOnStableMap(map);
    } else {
      known_info->CombineType(NodeType::kAnyHeapObject);
    }
  }
  return value;
}

ValueNode* MaglevGraphBuilder::BuildLoadFixedArrayLength(
    ValueNode* fixed_array) {
  ValueNode* length =
      BuildLoadTaggedField(fixed_array, offsetof(FixedArray, length_));
  EnsureType(length, NodeType::kSmi);
  return length;
}

ValueNode* MaglevGraphBuilder::BuildLoadJSArrayLength(ValueNode* js_array,
                                                      NodeType length_type) {
  // TODO(leszeks): JSArray.length is known to be non-constant, don't bother
  // searching the constant values.
  ReduceResult known_length =
      TryReuseKnownPropertyLoad(js_array, broker()->length_string());
  if (known_length.IsDone()) {
    DCHECK(known_length.IsDoneWithValue());
    return known_length.value();
  }

  ValueNode* length = BuildLoadTaggedField<LoadTaggedFieldForProperty>(
      js_array, JSArray::kLengthOffset, broker()->length_string());
  GetOrCreateInfoFor(length)->CombineType(length_type);
  RecordKnownProperty(js_array, broker()->length_string(), length, false,
                      compiler::AccessMode::kLoad);
  return length;
}

void MaglevGraphBuilder::BuildStoreMap(ValueNode* object, compiler::MapRef map,
                                       StoreMap::Kind kind) {
  AddNewNode<StoreMap>({object}, map, kind);
  NodeType object_type = StaticTypeForMap(map, broker());
  NodeInfo* node_info = GetOrCreateInfoFor(object);
  if (map.is_stable()) {
    node_info->SetPossibleMaps(PossibleMaps{map}, false, object_type, broker());
    broker()->dependencies()->DependOnStableMap(map);
  } else {
    node_info->SetPossibleMaps(PossibleMaps{map}, true, object_type, broker());
    known_node_aspects().any_map_for_any_node_is_unstable = true;
  }
}

ValueNode* MaglevGraphBuilder::BuildExtendPropertiesBackingStore(
    compiler::MapRef map, ValueNode* receiver, ValueNode* property_array) {
  int length = map.NextFreePropertyIndex() - map.GetInObjectProperties();
  // Under normal circumstances, NextFreePropertyIndex() will always be larger
  // than GetInObjectProperties(). However, an attacker able to corrupt heap
  // memory can break this invariant, in which case we'll get confused here,
  // potentially causing a sandbox violation. This CHECK defends against that.
  SBXCHECK_GE(length, 0);
  return AddNewNode<ExtendPropertiesBackingStore>({property_array, receiver},
                                                  length);
}

ReduceResult MaglevGraphBuilder::TryBuildStoreField(
    compiler::PropertyAccessInfo const& access_info, ValueNode* receiver,
    compiler::AccessMode access_mode) {
  FieldIndex field_index = access_info.field_index();
  Representation field_representation = access_info.field_representation();

  compiler::OptionalMapRef original_map;
  if (access_info.HasTransitionMap()) {
    compiler::MapRef transition = access_info.transition_map().value();
    original_map = transition.GetBackPointer(broker()).AsMap();

    if (original_map->UnusedPropertyFields() == 0) {
      DCHECK(!field_index.is_inobject());
    }
    if (!field_index.is_inobject()) {
      // If slack tracking ends after this compilation started but before it's
      // finished, then {original_map} could be out-of-sync with {transition}.
      // In particular, its UnusedPropertyFields could be non-zero, which would
      // lead us to not extend the property backing store, while the underlying
      // Map has actually zero UnusedPropertyFields. Thus, we install a
      // dependency on {orininal_map} now, so that if such a situation happens,
      // we'll throw away the code.
      broker()->dependencies()->DependOnNoSlackTrackingChange(*original_map);
    }
  } else if (access_info.IsFastDataConstant() &&
             access_mode == compiler::AccessMode::kStore) {
    return EmitUnconditionalDeopt(DeoptimizeReason::kStoreToConstant);
  }

  ValueNode* store_target;
  if (field_index.is_inobject()) {
    store_target = receiver;
  } else {
    // The field is in the property array, first load it from there.
    store_target =
        BuildLoadTaggedField(receiver, JSReceiver::kPropertiesOrHashOffset);
    if (original_map && original_map->UnusedPropertyFields() == 0) {
      store_target = BuildExtendPropertiesBackingStore(*original_map, receiver,
                                                       store_target);
    }
  }

  if (field_representation.IsDouble()) {
    ValueNode* float64_value = GetAccumulator();
    if (access_info.HasTransitionMap()) {
      // Allocate the mutable double box owned by the field.
      ValueNode* value =
          AddNewNode<Float64ToHeapNumberForField>({float64_value});
      BuildStoreTaggedField(store_target, value, field_index.offset(),
                            StoreTaggedMode::kTransitioning);
      BuildStoreMap(receiver, access_info.transition_map().value(),
                    StoreMap::Kind::kTransitioning);
    } else {
      AddNewNode<StoreDoubleField>({store_target, float64_value},
                                   field_index.offset());
    }
    return ReduceResult::Done();
  }

  ValueNode* value = GetAccumulator();
  if (field_representation.IsSmi()) {
    RETURN_IF_ABORT(GetAccumulatorSmi());
  } else {
    if (field_representation.IsHeapObject()) {
      // Emit a map check for the field type, if needed, otherwise just a
      // HeapObject check.
      if (access_info.field_map().has_value()) {
        RETURN_IF_ABORT(BuildCheckMaps(
            value, base::VectorOf({access_info.field_map().value()})));
      } else {
        BuildCheckHeapObject(value);
      }
    }
  }

  StoreTaggedMode store_mode = access_info.HasTransitionMap()
                                   ? StoreTaggedMode::kTransitioning
                                   : StoreTaggedMode::kDefault;
  if (field_representation.IsSmi()) {
    BuildStoreTaggedFieldNoWriteBarrier(store_target, value,
                                        field_index.offset(), store_mode);
  } else {
    DCHECK(field_representation.IsHeapObject() ||
           field_representation.IsTagged());
    BuildStoreTaggedField(store_target, value, field_index.offset(),
                          store_mode);
  }
  if (access_info.HasTransitionMap()) {
    BuildStoreMap(receiver, access_info.transition_map().value(),
                  StoreMap::Kind::kTransitioning);
  }

  return ReduceResult::Done();
}

namespace {
bool AccessInfoGuaranteedConst(
    compiler::PropertyAccessInfo const& access_info) {
  if (!access_info.IsFastDataConstant() && !access_info.IsStringLength()) {
    return false;
  }

  // Even if we have a constant load, if the map is not stable, we cannot
  // guarantee that the load is preserved across side-effecting calls.
  // TODO(v8:7700): It might be possible to track it as const if we know
  // that we're still on the main transition tree; and if we add a
  // dependency on the stable end-maps of the entire tree.
  for (auto& map : access_info.lookup_start_object_maps()) {
    if (!map.is_stable()) {
      return false;
    }
  }
  return true;
}
}  // namespace

ReduceResult MaglevGraphBuilder::TryBuildPropertyLoad(
    ValueNode* receiver, ValueNode* lookup_start_object, compiler::NameRef name,
    compiler::PropertyAccessInfo const& access_info) {
  if (access_info.holder().has_value() && !access_info.HasDictionaryHolder()) {
    broker()->dependencies()->DependOnStablePrototypeChains(
        access_info.lookup_start_object_maps(), kStartAtPrototype,
        access_info.holder().value());
  }

  switch (access_info.kind()) {
    case compiler::PropertyAccessInfo::kInvalid:
      UNREACHABLE();
    case compiler::PropertyAccessInfo::kNotFound:
      return GetRootConstant(RootIndex::kUndefinedValue);
    case compiler::PropertyAccessInfo::kDataField:
    case compiler::PropertyAccessInfo::kFastDataConstant: {
      ValueNode* result =
          BuildLoadField(access_info, lookup_start_object, name);
      RecordKnownProperty(lookup_start_object, name, result,
                          AccessInfoGuaranteedConst(access_info),
                          compiler::AccessMode::kLoad);
      return result;
    }
    case compiler::PropertyAccessInfo::kDictionaryProtoDataConstant: {
      compiler::OptionalObjectRef constant =
          TryFoldLoadDictPrototypeConstant(access_info);
      if (!constant.has_value()) return ReduceResult::Fail();
      return GetConstant(constant.value());
    }
    case compiler::PropertyAccessInfo::kFastAccessorConstant:
    case compiler::PropertyAccessInfo::kDictionaryProtoAccessorConstant:
      return TryBuildPropertyGetterCall(access_info, receiver,
                                        lookup_start_object);
    case compiler::PropertyAccessInfo::kModuleExport: {
      ValueNode* cell = GetConstant(access_info.constant().value().AsCell());
      return BuildLoadTaggedField<LoadTaggedFieldForProperty>(
          cell, Cell::kValueOffset, name);
    }
    case compiler::PropertyAccessInfo::kStringLength: {
      DCHECK_EQ(receiver, lookup_start_object);
      ValueNode* result = BuildLoadStringLength(receiver);
      RecordKnownProperty(lookup_start_object, name, result,
                          AccessInfoGuaranteedConst(access_info),
                          compiler::AccessMode::kLoad);
      return result;
    }
    case compiler::PropertyAccessInfo::kStringWrapperLength: {
      // TODO(dmercadier): update KnownNodeInfo.
      ValueNode* string = BuildLoadTaggedField(
          lookup_start_object, JSPrimitiveWrapper::kValueOffset);
      return AddNewNode<StringLength>({string});
    }
  }
}

ReduceResult MaglevGraphBuilder::TryBuildPropertyStore(
    ValueNode* receiver, ValueNode* lookup_start_object, compiler::NameRef name,
    compiler::PropertyAccessInfo const& access_info,
    compiler::AccessMode access_mode) {
  if (access_info.holder().has_value()) {
    broker()->dependencies()->DependOnStablePrototypeChains(
        access_info.lookup_start_object_maps(), kStartAtPrototype,
        access_info.holder().value());
  }

  switch (access_info.kind()) {
    case compiler::PropertyAccessInfo::kFastAccessorConstant: {
      return TryBuildPropertySetterCall(access_info, receiver,
                                        lookup_start_object, GetAccumulator());
    }
    case compiler::PropertyAccessInfo::kDataField:
    case compiler::PropertyAccessInfo::kFastDataConstant: {
      ReduceResult res = TryBuildStoreField(access_info, receiver, access_mode);
      if (res.IsDone()) {
        RecordKnownProperty(
            receiver, name, current_interpreter_frame_.accumulator(),
            AccessInfoGuaranteedConst(access_info), access_mode);
        return res;
      }
      return ReduceResult::Fail();
    }
    case compiler::PropertyAccessInfo::kInvalid:
    case compiler::PropertyAccessInfo::kNotFound:
    case compiler::PropertyAccessInfo::kDictionaryProtoDataConstant:
    case compiler::PropertyAccessInfo::kDictionaryProtoAccessorConstant:
    case compiler::PropertyAccessInfo::kModuleExport:
    case compiler::PropertyAccessInfo::kStringLength:
    case compiler::PropertyAccessInfo::kStringWrapperLength:
      UNREACHABLE();
  }
}

ReduceResult MaglevGraphBuilder::TryBuildPropertyAccess(
    ValueNode* receiver, ValueNode* lookup_start_object, compiler::NameRef name,
    compiler::PropertyAccessInfo const& access_info,
    compiler::AccessMode access_mode) {
  switch (access_mode) {
    case compiler::AccessMode::kLoad:
      return TryBuildPropertyLoad(receiver, lookup_start_object, name,
                                  access_info);
    case compiler::AccessMode::kStore:
    case compiler::AccessMode::kStoreInLiteral:
    case compiler::AccessMode::kDefine:
      DCHECK_EQ(receiver, lookup_start_object);
      return TryBuildPropertyStore(receiver, lookup_start_object, name,
                                   access_info, access_mode);
    case compiler::AccessMode::kHas:
      // TODO(victorgomes): BuildPropertyTest.
      return ReduceResult::Fail();
  }
}

template <typename GenericAccessFunc>
ReduceResult MaglevGraphBuilder::TryBuildNamedAccess(
    ValueNode* receiver, ValueNode* lookup_start_object,
    compiler::NamedAccessFeedback const& feedback,
    compiler::FeedbackSource const& feedback_source,
    compiler::AccessMode access_mode,
    GenericAccessFunc&& build_generic_access) {
  compiler::ZoneRefSet<Map> inferred_maps;

  if (compiler::OptionalHeapObjectRef c = TryGetConstant(lookup_start_object)) {
    compiler::MapRef constant_map = c.value().map(broker());
    if (c.value().IsJSFunction() &&
        feedback.name().equals(broker()->prototype_string())) {
      compiler::JSFunctionRef function = c.value().AsJSFunction();
      if (!constant_map.has_prototype_slot() ||
          !function.has_instance_prototype(broker()) ||
          function.PrototypeRequiresRuntimeLookup(broker()) ||
          access_mode != compiler::AccessMode::kLoad) {
        return ReduceResult::Fail();
      }
      compiler::HeapObjectRef prototype =
          broker()->dependencies()->DependOnPrototypeProperty(function);
      return GetConstant(prototype);
    }
    inferred_maps = compiler::ZoneRefSet<Map>(constant_map);
  } else if (feedback.maps().empty()) {
    // The IC is megamorphic.

    // We can't do megamorphic loads for lookups where the lookup start isn't
    // the receiver (e.g. load from super).
    if (receiver != lookup_start_object) return ReduceResult::Fail();

    // Use known possible maps if we have any.
    NodeInfo* object_info =
        known_node_aspects().TryGetInfoFor(lookup_start_object);
    if (object_info && object_info->possible_maps_are_known()) {
      inferred_maps = object_info->possible_maps();
    } else {
      // If we have no known maps, make the access megamorphic.
      switch (access_mode) {
        case compiler::AccessMode::kLoad:
          return BuildCallBuiltin<Builtin::kLoadIC_Megamorphic>(
              {GetTaggedValue(receiver), GetConstant(feedback.name())},
              feedback_source);
        case compiler::AccessMode::kStore:
          return BuildCallBuiltin<Builtin::kStoreIC_Megamorphic>(
              {GetTaggedValue(receiver), GetConstant(feedback.name()),
               GetTaggedValue(GetAccumulator())},
              feedback_source);
        case compiler::AccessMode::kDefine:
          return ReduceResult::Fail();
        case compiler::AccessMode::kHas:
        case compiler::AccessMode::kStoreInLiteral:
          UNREACHABLE();
      }
    }
  } else {
    // TODO(leszeks): This is doing duplicate work with BuildCheckMaps,
    // consider passing the merger into there.
    KnownMapsMerger merger(broker(), zone(), base::VectorOf(feedback.maps()));
    merger.IntersectWithKnownNodeAspects(lookup_start_object,
                                         known_node_aspects());
    inferred_maps = merger.intersect_set();
  }

  if (inferred_maps.is_empty()) {
    return EmitUnconditionalDeopt(DeoptimizeReason::kWrongMap);
  }

  ZoneVector<compiler::PropertyAccessInfo> access_infos(zone());
  ZoneVector<compiler::PropertyAccessInfo> access_infos_for_feedback(zone());

  for (compiler::MapRef map : inferred_maps) {
    if (map.is_deprecated()) continue;

    // TODO(v8:12547): Support writing to objects in shared space, which
    // need a write barrier that calls Object::Share to ensure the RHS is
    // shared.
    if (InstanceTypeChecker::IsAlwaysSharedSpaceJSObject(map.instance_type()) &&
        access_mode == compiler::AccessMode::kStore) {
      return ReduceResult::Fail();
    }

    compiler::PropertyAccessInfo access_info =
        broker()->GetPropertyAccessInfo(map, feedback.name(), access_mode);
    access_infos_for_feedback.push_back(access_info);
  }

  compiler::AccessInfoFactory access_info_factory(broker(), zone());
  if (!access_info_factory.FinalizePropertyAccessInfos(
          access_infos_for_feedback, access_mode, &access_infos)) {
    return ReduceResult::Fail();
  }

  // Check for monomorphic case.
  if (access_infos.size() == 1) {
    compiler::PropertyAccessInfo const& access_info = access_infos.front();
    base::Vector<const compiler::MapRef> maps =
        base::VectorOf(access_info.lookup_start_object_maps());
    if (HasOnlyStringMaps(maps)) {
      // Check for string maps before checking if we need to do an access
      // check. Primitive strings always get the prototype from the native
      // context they're operated on, so they don't need the access check.
      BuildCheckString(lookup_start_object);
    } else if (HasOnlyNumberMaps(maps)) {
      BuildCheckNumber(lookup_start_object);
    } else {
      RETURN_IF_ABORT(BuildCheckMaps(lookup_start_object, maps));
    }

    // Generate the actual property
    return TryBuildPropertyAccess(receiver, lookup_start_object,
                                  feedback.name(), access_info, access_mode);
  } else {
    // TODO(victorgomes): Unify control flow logic with
    // TryBuildPolymorphicElementAccess.
    return TryBuildPolymorphicPropertyAccess(
        receiver, lookup_start_object, feedback, access_mode, access_infos,
        build_generic_access);
  }
}

ValueNode* MaglevGraphBuilder::GetInt32ElementIndex(ValueNode* object) {
  RecordUseReprHintIfPhi(object, UseRepresentation::kInt32);

  switch (object->properties().value_representation()) {
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
    case ValueRepresentation::kTagged:
      NodeType old_type;
      if (SmiConstant* constant = object->TryCast<SmiConstant>()) {
        return GetInt32Constant(constant->value().value());
      } else if (CheckType(object, NodeType::kSmi, &old_type)) {
        auto& alternative = GetOrCreateInfoFor(object)->alternative();
        return alternative.get_or_set_int32(
            [&]() { return BuildSmiUntag(object); });
      } else {
        // TODO(leszeks): Cache this knowledge/converted value somehow on
        // the node info.
        return AddNewNode<CheckedObjectToIndex>({object},
                                                GetCheckType(old_type));
      }
    case ValueRepresentation::kInt32:
      // Already good.
      return object;
    case ValueRepresentation::kUint32:
    case ValueRepresentation::kFloat64:
    case ValueRepresentation::kHoleyFloat64:
      return GetInt32(object);
  }
}

// TODO(victorgomes): Consider caching the values and adding an
// uint32_alternative in node_info.
ReduceResult MaglevGraphBuilder::GetUint32ElementIndex(ValueNode* object) {
  // Don't record a Uint32 Phi use here, since the tagged path goes via
  // GetInt32ElementIndex, making this an Int32 Phi use.

  switch (object->properties().value_representation()) {
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
    case ValueRepresentation::kTagged:
      // TODO(victorgomes): Consider creating a CheckedObjectToUnsignedIndex.
      if (SmiConstant* constant = object->TryCast<SmiConstant>()) {
        int32_t value = constant->value().value();
        if (value < 0) {
          return EmitUnconditionalDeopt(DeoptimizeReason::kNotUint32);
        }
        return GetUint32Constant(value);
      }
      return AddNewNode<CheckedInt32ToUint32>({GetInt32ElementIndex(object)});
    case ValueRepresentation::kInt32:
      if (Int32Constant* constant = object->TryCast<Int32Constant>()) {
        int32_t value = constant->value();
        if (value < 0) {
          return EmitUnconditionalDeopt(DeoptimizeReason::kNotUint32);
        }
        return GetUint32Constant(value);
      }
      return AddNewNode<CheckedInt32ToUint32>({object});
    case ValueRepresentation::kUint32:
      return object;
    case ValueRepresentation::kFloat64:
      if (Float64Constant* constant = object->TryCast<Float64Constant>()) {
        double value = constant->value().get_scalar();
        uint32_t uint32_value;
        if (!DoubleToUint32IfEqualToSelf(value, &uint32_value)) {
          return EmitUnconditionalDeopt(DeoptimizeReason::kNotUint32);
        }
        if (Smi::IsValid(uint32_value)) {
          return GetUint32Constant(uint32_value);
        }
      }
      [[fallthrough]];
    case ValueRepresentation::kHoleyFloat64: {
      // CheckedTruncateFloat64ToUint32 will gracefully deopt on holes.
      return AddNewNode<CheckedTruncateFloat64ToUint32>({object});
    }
  }
}

ReduceResult MaglevGraphBuilder::TryBuildElementAccessOnString(
    ValueNode* object, ValueNode* index_object,
    compiler::KeyedAccessMode const& keyed_mode) {
  // Strings are immutable and `in` cannot be used on strings
  if (keyed_mode.access_mode() != compiler::AccessMode::kLoad) {
    return ReduceResult::Fail();
  }

  // Ensure that {object} is actually a String.
  BuildCheckString(object);

  ValueNode* length = BuildLoadStringLength(object);
  ValueNode* index = GetInt32ElementIndex(index_object);
  auto emit_load = [&] { return AddNewNode<StringAt>({object, index}); };

  if (LoadModeHandlesOOB(keyed_mode.load_mode()) &&
      broker()->dependencies()->DependOnNoElementsProtector()) {
    ValueNode* positive_index;
    GET_VALUE_OR_ABORT(positive_index, GetUint32ElementIndex(index));
    ValueNode* uint32_length = AddNewNode<UnsafeInt32ToUint32>({length});
    return Select(
        [&](auto& builder) {
          return BuildBranchIfUint32Compare(builder, Operation::kLessThan,
                                            positive_index, uint32_length);
        },
        emit_load, [&] { return GetRootConstant(RootIndex::kUndefinedValue); });
  } else {
    RETURN_IF_ABORT(TryBuildCheckInt32Condition(
        index, length, AssertCondition::kUnsignedLessThan,
        DeoptimizeReason::kOutOfBounds));
    return emit_load();
  }
}

namespace {
ReduceResult TryFindLoadedProperty(
    const KnownNodeAspects::LoadedPropertyMap& loaded_properties,
    ValueNode* lookup_start_object,
    KnownNodeAspects::LoadedPropertyMapKey name) {
  auto props_for_name = loaded_properties.find(name);
  if (props_for_name == loaded_properties.end()) return ReduceResult::Fail();

  auto it = props_for_name->second.find(lookup_start_object);
  if (it == props_for_name->second.end()) return ReduceResult::Fail();

  return it->second;
}

bool CheckConditionIn32(int32_t lhs, int32_t rhs, AssertCondition condition) {
  switch (condition) {
    case AssertCondition::kEqual:
      return lhs == rhs;
    case AssertCondition::kNotEqual:
      return lhs != rhs;
    case AssertCondition::kLessThan:
      return lhs < rhs;
    case AssertCondition::kLessThanEqual:
      return lhs <=
```