Response:
The user wants me to analyze the provided C++ code snippet from V8's `js-native-context-specialization.cc`. I need to summarize its functionality, relate it to JavaScript concepts, provide examples, and consider common programming errors if applicable.

Here's a breakdown of the thinking process:

1. **Identify the Core Functionality:** The code is part of the TurboFan compiler in V8. The filename hints at "specialization" related to the JavaScript native context. The functions within the snippet focus on optimizing property and element access in JavaScript. Keywords like `ReduceElementAccess`, `ReducePropertyAccess`, `BuildElementAccess`, `BuildPropertyLoad`, and `InlinePropertyGetterCall` are crucial.

2. **Connect to JavaScript Concepts:**
    * **Property Access:**  This directly relates to how you access properties of JavaScript objects (e.g., `object.property`, `object['property']`).
    * **Element Access:** This corresponds to accessing elements in arrays or array-like objects (e.g., `array[index]`).
    * **Type Feedback:** The code heavily uses `feedback` to guide optimization. This ties into JavaScript's dynamic typing; the engine learns about object shapes and types during runtime to optimize future accesses.
    * **Prototypes:** The code explicitly deals with prototype chains and how they influence property lookup and setters.
    * **Accessors (Getters/Setters):**  The code handles cases where properties are defined with getter/setter functions.
    * **`in` operator:** The `ReduceJSHasProperty` function relates to the `in` operator in JavaScript.
    * **`for...in` loop:** The `ReduceJSLoadPropertyWithEnumeratedKey` function targets optimizations within `for...in` loops.
    * **Typed Arrays:** The code mentions handling `Float16Array` specifically, demonstrating awareness of typed arrays in JavaScript.
    * **Constant Folding:**  The `ReduceElementLoadFromHeapConstant` function aims to optimize loads from objects with known constant values at compile time.
    * **Strings:**  The code optimizes access to characters within strings.

3. **Illustrate with JavaScript Examples:**  For each identified concept, create a simple JavaScript code snippet that demonstrates it. This helps to make the C++ code's purpose more concrete.

4. **Infer Code Logic and Provide Examples:** Look for specific scenarios within the code, such as:
    * **Monomorphic vs. Polymorphic Access:** The code differentiates between accessing a property of objects with the same "shape" (monomorphic) and objects with different "shapes" (polymorphic).
    * **Elements Kind Transitions:** The code mentions "elements kind transitions," which refers to how V8 might change the internal representation of an array's elements for optimization (e.g., from `PACKED_SMI_ELEMENTS` to `PACKED_DOUBLE_ELEMENTS`).
    * **Prototype Chain Checks:**  Illustrate how the prototype chain is traversed during property access and how setters on prototypes can affect optimization.

5. **Consider Common Programming Errors:** Think about typical mistakes JavaScript developers make that might relate to the optimizations being discussed.
    * **Accessing non-existent properties:**  Relate this to the "IsNotFound" case in the C++ code.
    * **Modifying objects in ways that invalidate optimizations:** Explain how changes to object structure can cause deoptimization.
    * **Performance implications of polymorphic code:**  Explain why monomorphic code is generally faster.

6. **Synthesize the Functionality Summary:** Based on the analysis, write a concise summary of the code's purpose. Emphasize that it's about optimizing property and element access within the V8 compiler.

7. **Address the `.tq` Question:** Explicitly state that if the file ended in `.tq`, it would be Torque code, another language used within V8.

8. **Structure the Response:** Organize the information into clear sections as requested by the prompt. Use headings and bullet points for readability.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** Focus solely on the individual functions.
* **Correction:** Realize that the functions work together to implement a larger optimization strategy. The summary should reflect this broader purpose.
* **Initial thought:** Provide very technical examples.
* **Correction:**  Simplify the JavaScript examples to make them more accessible and directly relevant to the C++ snippets.
* **Initial thought:**  Overlook the `.tq` question.
* **Correction:**  Remember to explicitly address all parts of the prompt.
* **Initial thought:** Not clearly connect the C++ code to high-level JavaScript concepts.
* **Correction:**  Emphasize the connection to property access, element access, type feedback, and prototypes to provide context.
好的，让我们来分析一下这段 V8 源代码 `v8/src/compiler/js-native-context-specialization.cc` 的功能。

**功能归纳：**

这段代码是 V8 编译器中用于**基于 JavaScript 原生上下文信息进行优化的一个重要组成部分**。它专注于优化 JavaScript 中**属性和元素的访问操作**（包括加载、存储、检查是否存在等）。通过分析类型反馈信息和对象结构，编译器尝试生成更高效的机器码，避免一些运行时的检查和查找，从而提升性能。

**详细功能列表：**

1. **元素访问优化 (Element Access Optimization):**
   - `ReduceElementAccess`:  根据类型反馈信息，针对数组或类似数组对象的元素访问（例如 `array[index]`）进行优化。
   -  处理不同类型的元素存储模式（例如，是否允许存储空洞，是否会增长）。
   -  根据元素类型（例如，`Float16Array`）进行特殊处理。
   -  处理原型链上是否存在元素访问的 setter。
   -  处理单态（只有一个可能的对象类型）和多态（多个可能的对象类型）的元素访问情况。
   -  进行元素类型转换的优化 (`TransitionElementsKind`).
   -  插入 MapCheck 来验证对象类型。
   -  调用 `BuildElementAccess` 来生成实际的元素访问代码。

2. **常量元素加载优化 (Constant Element Load Optimization):**
   - `ReduceElementLoadFromHeapConstant`:  当访问对象的已知常量元素时（例如，访问字符串的特定字符），尝试在编译时进行常量折叠。
   -  处理访问字符串的场景，并利用字符串长度进行优化。

3. **属性访问优化 (Property Access Optimization):**
   - `ReducePropertyAccess`:  这是属性访问优化的核心函数，根据类型反馈信息 `feedback`，分派到不同的优化路径。
   -  处理命名属性访问（例如 `object.property`）和索引属性访问（例如 `object['property']`）。
   -  根据 `feedback` 的类型（`kNamedAccess`, `kElementAccess` 等）调用不同的处理函数。
   -  处理 `MegaDOMPropertyAccess` (与 DOM 相关的属性访问优化)。

4. **类型反馈处理 (Type Feedback Handling):**
   - 代码中大量使用了 `ProcessedFeedback`，这意味着它依赖于 V8 运行时收集的类型反馈信息。这些信息指导编译器进行有针对性的优化。
   -  当类型反馈不足时，可能会触发 `ReduceEagerDeoptimize`，导致代码回退到未优化的状态。

5. **`in` 操作符优化 (`JSHasProperty`):**
   - `ReduceJSHasProperty`:  优化 JavaScript 的 `in` 操作符，用于检查对象是否拥有某个属性。

6. **`for...in` 循环中的属性加载优化 (`ReduceJSLoadPropertyWithEnumeratedKey`):**
   -  针对 `for...in` 循环内部的属性加载进行优化。
   -  当 `for...in` 循环处于快速模式时，可以利用枚举缓存的信息。
   -  通过 MapCheck 和加载字段值的方式优化属性访问。

7. **属性 Getter 和 Setter 内联 (Inline Property Getter/Setter Call):**
   - `InlinePropertyGetterCall` 和 `InlinePropertySetterCall`:  如果属性有 getter 或 setter，并且可以确定其实现，则尝试将 getter 或 setter 函数的调用内联到调用点，避免函数调用的开销。
   -  处理 API 调用的内联。

8. **API 调用内联 (Inline API Call):**
   - `InlineApiCall`:  内联与 C++ 代码关联的 API 函数调用。

9. **属性加载构建 (BuildPropertyLoad):**
   -  根据 `PropertyAccessInfo` 中的信息，构建实际的属性加载操作。
   -  处理不同的属性类型，例如数据属性、访问器属性、模块导出等。

10. **属性测试构建 (BuildPropertyTest):**
    -  （代码片段未完整显示，但根据命名推测）可能用于构建用于属性测试（例如，使用 `in` 操作符）的代码。

**关于 `.tq` 结尾:**

如果 `v8/src/compiler/js-native-context-specialization.cc` 以 `.tq` 结尾，那么它将是 **V8 Torque 源代码**。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。  `.cc` 结尾表示它是标准的 C++ 源代码。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这段 C++ 代码直接影响 JavaScript 代码的执行性能。它优化了 JavaScript 中常见的属性和元素访问模式。

**JavaScript 示例：**

```javascript
// 元素访问优化
const arr = [1, 2, 3];
const firstElement = arr[0]; // ReduceElementAccess 会优化此操作

// 常量元素加载优化
const str = "hello";
const firstChar = str[0]; // ReduceElementLoadFromHeapConstant 会优化此操作

// 属性访问优化
const obj = { a: 1, b: 2 };
const valueOfA = obj.a; // ReducePropertyAccess 会优化此操作

// in 操作符优化
if ('a' in obj) { // ReduceJSHasProperty 会优化此操作
  console.log('obj has property a');
}

// for...in 循环中的属性加载优化
const myObj = { x: 10, y: 20 };
for (const key in myObj) {
  const value = myObj[key]; // ReduceJSLoadPropertyWithEnumeratedKey 会优化此操作
  console.log(key, value);
}

// Getter 内联
const myObject = {
  _value: 5,
  get doubleValue() {
    return this._value * 2;
  }
};
const doubled = myObject.doubleValue; // InlinePropertyGetterCall 可能会内联 getter
```

**代码逻辑推理与假设输入输出：**

假设有以下 JavaScript 代码：

```javascript
function getElement(arr, index) {
  return arr[index];
}

const myArray = [10, 20, 30];
const result = getElement(myArray, 1);
```

**在 `ReduceElementAccess` 中：**

* **假设输入：**
    * `node`: 代表 `arr[index]` 操作的节点。
    * `receiver`: 代表 `arr` 的节点。
    * `index`: 代表 `index` 的节点。
    * `access_infos`: 可能包含关于 `myArray` 的类型信息（例如，它是 PackedSmiElements 的数组）。
    * `access_mode`: `AccessMode::kLoad`。
* **代码逻辑推理：**
    * 代码会检查 `access_infos`，如果 `myArray` 的元素类型是已知的且是稳定的，则可以跳过一些运行时的类型检查。
    * 如果是单态访问（通常只访问相同类型的数组），则可以生成更直接的内存访问指令。
    * 代码可能会生成类似 "加载 `myArray` 中索引为 `index` 的元素" 的指令。
* **可能的输出 (简化的指令)：**
    * 如果 `myArray` 是 `PACKED_SMI_ELEMENTS` 并且索引是有效的，则可能生成直接从内存加载整数的指令。

**涉及用户常见的编程错误：**

1. **访问不存在的属性或索引：**
   ```javascript
   const obj = {};
   console.log(obj.nonExistentProperty); //  会导致返回 undefined，相关的优化代码会处理 "IsNotFound" 的情况。

   const arr = [1, 2];
   console.log(arr[5]); // 访问越界索引，相关的优化代码需要考虑这种情况。
   ```
   V8 的优化器会尝试针对常见的情况进行优化，但如果代码总是访问不存在的属性或索引，这些优化可能不会带来太多收益。

2. **频繁修改对象结构，导致类型反馈失效：**
   ```javascript
   const obj = { a: 1 };
   // ... 很多操作 ...
   obj.b = 2; // 添加新属性，改变了对象的“形状”

   console.log(obj.b); // 之前的针对 obj 的 'a' 属性的优化可能失效，需要重新进行类型反馈和优化。
   ```
   频繁地添加或删除属性，或者改变属性的类型，会导致 V8 的类型反馈信息变得过时，从而降低优化的效果，甚至触发反优化。

3. **在原型链上使用 setter 产生意外副作用：**
   ```javascript
   const proto = {
     set x(value) {
       console.log('Setting x:', value);
       this._x = value;
     },
     get x() {
       return this._x;
     }
   };
   const obj = Object.create(proto);
   obj.x = 10; // 触发原型链上的 setter
   console.log(obj.x);
   ```
   V8 在优化属性访问时会考虑原型链上的 setter。如果 setter 有副作用，优化器需要确保这些副作用能够正确执行。不理解原型链和 setter 的行为可能导致性能问题或意外的程序行为。

**总结 `v8/src/compiler/js-native-context-specialization.cc` 的功能 (作为第 4 部分)：**

作为 V8 编译器优化流程的一部分，`v8/src/compiler/js-native-context-specialization.cc` 专注于**利用 JavaScript 原生上下文信息来优化属性和元素的访问操作**。它通过分析类型反馈、对象结构和原型链等信息，尝试在编译时生成更高效的机器码，减少运行时的开销。这段代码处理了多种属性和元素访问的场景，包括加载、存储、检查存在性以及与 `for...in` 循环和 getter/setter 相关的优化。其目标是提升 JavaScript 代码在 V8 引擎上的执行效率。

Prompt: 
```
这是目录为v8/src/compiler/js-native-context-specialization.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-native-context-specialization.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
f the compiler.
  // TODO(v8:14012): We could lower further here and emit LoadTypedElement (like
  // we do for other typed arrays). However, given the lack of hardware support
  // for Float16 operations, it's not clear whether optimizing further would be
  // really useful.
  for (const ElementAccessInfo& access_info : access_infos) {
    if (IsFloat16TypedArrayElementsKind(access_info.elements_kind())) {
      return NoChange();
    }
  }

  // For holey stores or growing stores, we need to check that the prototype
  // chain contains no setters for elements, and we need to guard those checks
  // via code dependencies on the relevant prototype maps.
  if (access_mode == AccessMode::kStore) {
    // TODO(turbofan): We could have a fast path here, that checks for the
    // common case of Array or Object prototype only and therefore avoids
    // the zone allocation of this vector.
    ZoneVector<MapRef> prototype_maps(zone());
    for (ElementAccessInfo const& access_info : access_infos) {
      for (MapRef receiver_map : access_info.lookup_start_object_maps()) {
        // If the {receiver_map} has a prototype and its elements backing
        // store is either holey, or we have a potentially growing store,
        // then we need to check that all prototypes have stable maps with
        // no element accessors and no throwing behavior for elements (and we
        // need to guard against changes to that below).
        if ((IsHoleyOrDictionaryElementsKind(receiver_map.elements_kind()) ||
             StoreModeCanGrow(feedback.keyed_mode().store_mode())) &&
            !receiver_map.PrototypesElementsDoNotHaveAccessorsOrThrow(
                broker(), &prototype_maps)) {
          return NoChange();
        }

        // TODO(v8:12547): Support writing to objects in shared space, which
        // need a write barrier that calls Object::Share to ensure the RHS is
        // shared.
        if (InstanceTypeChecker::IsAlwaysSharedSpaceJSObject(
                receiver_map.instance_type())) {
          return NoChange();
        }
      }
    }
    for (MapRef prototype_map : prototype_maps) {
      dependencies()->DependOnStableMap(prototype_map);
    }
  } else if (access_mode == AccessMode::kHas) {
    // If we have any fast arrays, we need to check and depend on
    // NoElementsProtector.
    for (ElementAccessInfo const& access_info : access_infos) {
      if (IsFastElementsKind(access_info.elements_kind())) {
        if (!dependencies()->DependOnNoElementsProtector()) return NoChange();
        break;
      }
    }
  }

  // Check for the monomorphic case.
  PropertyAccessBuilder access_builder(jsgraph(), broker());
  if (access_infos.size() == 1) {
    ElementAccessInfo access_info = access_infos.front();

    // Perform possible elements kind transitions.
    MapRef transition_target = access_info.lookup_start_object_maps().front();
    for (MapRef transition_source : access_info.transition_sources()) {
      DCHECK_EQ(access_info.lookup_start_object_maps().size(), 1);
      effect = graph()->NewNode(
          simplified()->TransitionElementsKind(ElementsTransition(
              IsSimpleMapChangeTransition(transition_source.elements_kind(),
                                          transition_target.elements_kind())
                  ? ElementsTransition::kFastTransition
                  : ElementsTransition::kSlowTransition,
              transition_source, transition_target)),
          receiver, effect, control);
    }

    // TODO(turbofan): The effect/control linearization will not find a
    // FrameState after the StoreField or Call that is generated for the
    // elements kind transition above. This is because those operators
    // don't have the kNoWrite flag on it, even though they are not
    // observable by JavaScript.
    Node* frame_state =
        NodeProperties::FindFrameStateBefore(node, jsgraph()->Dead());
    effect =
        graph()->NewNode(common()->Checkpoint(), frame_state, effect, control);

    // Perform map check on the {receiver}.
    access_builder.BuildCheckMaps(receiver, &effect, control,
                                  access_info.lookup_start_object_maps());

    // Access the actual element.
    ValueEffectControl continuation =
        BuildElementAccess(receiver, index, value, effect, control, context,
                           access_info, feedback.keyed_mode());
    value = continuation.value();
    effect = continuation.effect();
    control = continuation.control();
  } else {
    // The final states for every polymorphic branch. We join them with
    // Merge+Phi+EffectPhi at the bottom.
    ZoneVector<Node*> values(zone());
    ZoneVector<Node*> effects(zone());
    ZoneVector<Node*> controls(zone());

    // Generate code for the various different element access patterns.
    Node* fallthrough_control = control;
    for (size_t j = 0; j < access_infos.size(); ++j) {
      ElementAccessInfo const& access_info = access_infos[j];
      Node* this_receiver = receiver;
      Node* this_value = value;
      Node* this_index = index;
      Effect this_effect = effect;
      Control this_control{fallthrough_control};

      // Perform possible elements kind transitions.
      MapRef transition_target = access_info.lookup_start_object_maps().front();
      for (MapRef transition_source : access_info.transition_sources()) {
        DCHECK_EQ(access_info.lookup_start_object_maps().size(), 1);
        this_effect = graph()->NewNode(
            simplified()->TransitionElementsKind(ElementsTransition(
                IsSimpleMapChangeTransition(transition_source.elements_kind(),
                                            transition_target.elements_kind())
                    ? ElementsTransition::kFastTransition
                    : ElementsTransition::kSlowTransition,
                transition_source, transition_target)),
            receiver, this_effect, this_control);
      }

      // Perform map check(s) on {receiver}.
      ZoneVector<MapRef> const& receiver_maps =
          access_info.lookup_start_object_maps();
      if (j == access_infos.size() - 1) {
        // Last map check on the fallthrough control path, do a
        // conditional eager deoptimization exit here.
        access_builder.BuildCheckMaps(receiver, &this_effect, this_control,
                                      receiver_maps);
        fallthrough_control = nullptr;
      } else {
        // Explicitly branch on the {receiver_maps}.
        ZoneRefSet<Map> maps(receiver_maps.begin(), receiver_maps.end(),
                             graph()->zone());
        Node* check = this_effect =
            graph()->NewNode(simplified()->CompareMaps(maps), receiver,
                             this_effect, fallthrough_control);
        Node* branch =
            graph()->NewNode(common()->Branch(), check, fallthrough_control);
        fallthrough_control = graph()->NewNode(common()->IfFalse(), branch);
        this_control = graph()->NewNode(common()->IfTrue(), branch);

        // Introduce a MapGuard to learn from this on the effect chain.
        this_effect = graph()->NewNode(simplified()->MapGuard(maps), receiver,
                                       this_effect, this_control);
      }

      // Access the actual element.
      ValueEffectControl continuation = BuildElementAccess(
          this_receiver, this_index, this_value, this_effect, this_control,
          context, access_info, feedback.keyed_mode());
      values.push_back(continuation.value());
      effects.push_back(continuation.effect());
      controls.push_back(continuation.control());
    }

    DCHECK_NULL(fallthrough_control);

    // Generate the final merge point for all (polymorphic) branches.
    int const control_count = static_cast<int>(controls.size());
    if (control_count == 0) {
      value = effect = control = jsgraph()->Dead();
    } else if (control_count == 1) {
      value = values.front();
      effect = effects.front();
      control = controls.front();
    } else {
      control = graph()->NewNode(common()->Merge(control_count), control_count,
                                 &controls.front());
      values.push_back(control);
      value = graph()->NewNode(
          common()->Phi(MachineRepresentation::kTagged, control_count),
          control_count + 1, &values.front());
      effects.push_back(control);
      effect = graph()->NewNode(common()->EffectPhi(control_count),
                                control_count + 1, &effects.front());
    }
  }

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSNativeContextSpecialization::ReduceElementLoadFromHeapConstant(
    Node* node, Node* key, AccessMode access_mode,
    KeyedAccessLoadMode load_mode) {
  DCHECK(node->opcode() == IrOpcode::kJSLoadProperty ||
         node->opcode() == IrOpcode::kJSHasProperty);
  Node* receiver = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  HeapObjectMatcher mreceiver(receiver);
  HeapObjectRef receiver_ref = mreceiver.Ref(broker());
  if (receiver_ref.IsNull() || receiver_ref.IsUndefined() ||
      // The 'in' operator throws a TypeError on primitive values.
      (receiver_ref.IsString() && access_mode == AccessMode::kHas)) {
    return NoChange();
  }

  // Check whether we're accessing a known element on the {receiver} and can
  // constant-fold the load.
  NumberMatcher mkey(key);
  if (mkey.IsInteger() &&
      mkey.IsInRange(0.0, static_cast<double>(JSObject::kMaxElementIndex))) {
    static_assert(JSObject::kMaxElementIndex <= kMaxUInt32);
    const uint32_t index = static_cast<uint32_t>(mkey.ResolvedValue());
    OptionalObjectRef element;

    if (receiver_ref.IsJSObject()) {
      JSObjectRef jsobject_ref = receiver_ref.AsJSObject();
      OptionalFixedArrayBaseRef elements =
          jsobject_ref.elements(broker(), kRelaxedLoad);
      if (elements.has_value()) {
        element = jsobject_ref.GetOwnConstantElement(broker(), *elements, index,
                                                     dependencies());
        if (!element.has_value() && receiver_ref.IsJSArray()) {
          // We didn't find a constant element, but if the receiver is a
          // cow-array we can exploit the fact that any future write to the
          // element will replace the whole elements storage.
          element = receiver_ref.AsJSArray().GetOwnCowElement(broker(),
                                                              *elements, index);
          if (element.has_value()) {
            Node* actual_elements = effect = graph()->NewNode(
                simplified()->LoadField(AccessBuilder::ForJSObjectElements()),
                receiver, effect, control);
            Node* check = graph()->NewNode(
                simplified()->ReferenceEqual(), actual_elements,
                jsgraph()->ConstantNoHole(*elements, broker()));
            effect = graph()->NewNode(
                simplified()->CheckIf(
                    DeoptimizeReason::kCowArrayElementsChanged),
                check, effect, control);
          }
        }
      }
    } else if (receiver_ref.IsString()) {
      element =
          receiver_ref.AsString().GetCharAsStringOrUndefined(broker(), index);
    }

    if (element.has_value()) {
      Node* value = access_mode == AccessMode::kHas
                        ? jsgraph()->TrueConstant()
                        : jsgraph()->ConstantNoHole(*element, broker());
      ReplaceWithValue(node, value, effect, control);
      return Replace(value);
    }
  }

  // For constant Strings we can eagerly strength-reduce the keyed
  // accesses using the known length, which doesn't change.
  if (receiver_ref.IsString()) {
    DCHECK_NE(access_mode, AccessMode::kHas);
    // Ensure that {key} is less than {receiver} length.
    Node* length = jsgraph()->ConstantNoHole(receiver_ref.AsString().length());

    // Load the single character string from {receiver} or yield
    // undefined if the {key} is out of bounds (depending on the
    // {load_mode}).
    Node* value = BuildIndexedStringLoad(receiver, key, length, &effect,
                                         &control, load_mode);
    ReplaceWithValue(node, value, effect, control);
    return Replace(value);
  }

  return NoChange();
}

Reduction JSNativeContextSpecialization::ReducePropertyAccess(
    Node* node, Node* key, OptionalNameRef static_name, Node* value,
    FeedbackSource const& source, AccessMode access_mode) {
  DCHECK_EQ(key == nullptr, static_name.has_value());
  DCHECK(node->opcode() == IrOpcode::kJSLoadProperty ||
         node->opcode() == IrOpcode::kJSSetKeyedProperty ||
         node->opcode() == IrOpcode::kJSStoreInArrayLiteral ||
         node->opcode() == IrOpcode::kJSDefineKeyedOwnPropertyInLiteral ||
         node->opcode() == IrOpcode::kJSHasProperty ||
         node->opcode() == IrOpcode::kJSLoadNamed ||
         node->opcode() == IrOpcode::kJSSetNamedProperty ||
         node->opcode() == IrOpcode::kJSDefineNamedOwnProperty ||
         node->opcode() == IrOpcode::kJSLoadNamedFromSuper ||
         node->opcode() == IrOpcode::kJSDefineKeyedOwnProperty);
  DCHECK_GE(node->op()->ControlOutputCount(), 1);

  ProcessedFeedback const* feedback =
      &broker()->GetFeedbackForPropertyAccess(source, access_mode, static_name);

  if (feedback->kind() == ProcessedFeedback::kElementAccess &&
      feedback->AsElementAccess().transition_groups().empty()) {
    HeapObjectMatcher m_key(key);
    if (m_key.HasResolvedValue() && m_key.Ref(broker()).IsName()) {
      NameRef name_key = m_key.Ref(broker()).AsName();
      if (name_key.IsUniqueName() && !name_key.object()->IsArrayIndex()) {
        feedback = &feedback->AsElementAccess().Refine(
            broker(), m_key.Ref(broker()).AsName());
      }
    }
  }

  switch (feedback->kind()) {
    case ProcessedFeedback::kInsufficient:
      return ReduceEagerDeoptimize(
          node,
          DeoptimizeReason::kInsufficientTypeFeedbackForGenericNamedAccess);
    case ProcessedFeedback::kNamedAccess:
      return ReduceNamedAccess(node, value, feedback->AsNamedAccess(),
                               access_mode, key);
    case ProcessedFeedback::kMegaDOMPropertyAccess:
      DCHECK_EQ(access_mode, AccessMode::kLoad);
      DCHECK_NULL(key);
      return ReduceMegaDOMPropertyAccess(
          node, value, feedback->AsMegaDOMPropertyAccess(), source);
    case ProcessedFeedback::kElementAccess:
      DCHECK_EQ(feedback->AsElementAccess().keyed_mode().access_mode(),
                access_mode);
      DCHECK_NE(node->opcode(), IrOpcode::kJSLoadNamedFromSuper);
      return ReduceElementAccess(node, key, value, feedback->AsElementAccess());
    default:
      UNREACHABLE();
  }
}

Reduction JSNativeContextSpecialization::ReduceEagerDeoptimize(
    Node* node, DeoptimizeReason reason) {
  if (!(flags() & kBailoutOnUninitialized)) return NoChange();

  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* frame_state =
      NodeProperties::FindFrameStateBefore(node, jsgraph()->Dead());
  Node* deoptimize =
      graph()->NewNode(common()->Deoptimize(reason, FeedbackSource()),
                       frame_state, effect, control);
  MergeControlToEnd(graph(), common(), deoptimize);
  node->TrimInputCount(0);
  NodeProperties::ChangeOp(node, common()->Dead());
  return Changed(node);
}

Reduction JSNativeContextSpecialization::ReduceJSHasProperty(Node* node) {
  JSHasPropertyNode n(node);
  PropertyAccess const& p = n.Parameters();
  Node* value = jsgraph()->Dead();
  if (!p.feedback().IsValid()) return NoChange();
  return ReducePropertyAccess(node, n.key(), std::nullopt, value,
                              FeedbackSource(p.feedback()), AccessMode::kHas);
}

Reduction JSNativeContextSpecialization::ReduceJSLoadPropertyWithEnumeratedKey(
    Node* node) {
  // We can optimize a property load if it's being used inside a for..in:
  //   for (name in receiver) {
  //     value = receiver[name];
  //     ...
  //   }
  //
  // If the for..in is in fast-mode, we know that the {receiver} has {name}
  // as own property, otherwise the enumeration wouldn't include it. The graph
  // constructed by the BytecodeGraphBuilder in this case looks like this:

  // receiver
  //  ^    ^
  //  |    |
  //  |    +-+
  //  |      |
  //  |   JSToObject
  //  |      ^
  //  |      |
  //  |      |
  //  |  JSForInNext
  //  |      ^
  //  |      |
  //  +----+ |
  //       | |
  //       | |
  //   JSLoadProperty

  // If the for..in has only seen maps with enum cache consisting of keys
  // and indices so far, we can turn the {JSLoadProperty} into a map check
  // on the {receiver} and then just load the field value dynamically via
  // the {LoadFieldByIndex} operator. The map check is only necessary when
  // TurboFan cannot prove that there is no observable side effect between
  // the {JSForInNext} and the {JSLoadProperty} node.
  //
  // We can do a similar optimization when the receiver of {JSLoadProperty} is
  // not identical to the receiver of {JSForInNext}:
  //   for (name in receiver) {
  //     value = object[name];
  //     ...
  //   }
  //
  // This is because when the key is {JSForInNext}, we will generate a
  // {GetEnumeratedKeyedProperty} bytecode for {JSLoadProperty}. If the bytecode
  // always manages to use the enum cache, we will keep the inline cache in
  // uninitialized state. So If the graph is as below, we can firstly do a map
  // check on {object} and then turn the {JSLoadProperty} into the
  // {LoadFieldByIndex}. This is also safe when the bytecode has never been
  // profiled. When it happens to pass the the map check, we can use the fast
  // path. Otherwise it will trigger a deoptimization.

  // object     receiver
  //  ^             ^
  //  |             |
  //  |             |
  //  |             |
  //  |        JSToObject
  //  |             ^
  //  |             |
  //  |             |
  //  |        JSForInNext
  //  |             ^
  //  |             |
  //  +----+  +-----+
  //       |  |
  //       |  |
  //   JSLoadProperty (insufficient feedback)

  // Also note that it's safe to look through the {JSToObject}, since the
  // [[Get]] operation does an implicit ToObject anyway, and these operations
  // are not observable.

  DCHECK_EQ(IrOpcode::kJSLoadProperty, node->opcode());
  Node* receiver = NodeProperties::GetValueInput(node, 0);
  JSForInNextNode name(NodeProperties::GetValueInput(node, 1));
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  if (name.Parameters().mode() != ForInMode::kUseEnumCacheKeysAndIndices) {
    return NoChange();
  }

  Node* object = name.receiver();
  Node* cache_type = name.cache_type();
  Node* index = name.index();
  if (object->opcode() == IrOpcode::kJSToObject) {
    object = NodeProperties::GetValueInput(object, 0);
  }
  bool speculating_object_is_receiver = false;
  if (object != receiver) {
    JSLoadPropertyNode n(node);
    PropertyAccess const& p = n.Parameters();

    ProcessedFeedback const& feedback = broker()->GetFeedbackForPropertyAccess(
        FeedbackSource(p.feedback()), AccessMode::kLoad, std::nullopt);
    // When the feedback is uninitialized, it is either a load from a
    // {GetEnumeratedKeyedProperty} which always hits the enum cache, or a keyed
    // load that had never been reached. In either case, we can check the map
    // of the receiver and use the enum cache if the map match the {cache_type}.
    if (feedback.kind() != ProcessedFeedback::kInsufficient) {
      return NoChange();
    }

    // Ensure that {receiver} is a HeapObject.
    receiver = effect = graph()->NewNode(simplified()->CheckHeapObject(),
                                         receiver, effect, control);
    speculating_object_is_receiver = true;
  }

  // No need to repeat the map check if we can prove that there's no
  // observable side effect between {effect} and {name]. But we always need a
  // map check when {object} is not identical to {receiver}.
  if (!NodeProperties::NoObservableSideEffectBetween(effect, name) ||
      speculating_object_is_receiver) {
    // Check that the {receiver} map is still valid.
    Node* receiver_map = effect =
        graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()),
                         receiver, effect, control);
    Node* check = graph()->NewNode(simplified()->ReferenceEqual(), receiver_map,
                                   cache_type);
    effect =
        graph()->NewNode(simplified()->CheckIf(DeoptimizeReason::kWrongMap),
                         check, effect, control);
  }

  // Load the enum cache indices from the {cache_type}.
  Node* descriptor_array = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapDescriptors()), cache_type,
      effect, control);
  Node* enum_cache = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForDescriptorArrayEnumCache()),
      descriptor_array, effect, control);
  Node* enum_indices = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForEnumCacheIndices()), enum_cache,
      effect, control);

  // Ensure that the {enum_indices} are valid.
  Node* check = graph()->NewNode(
      simplified()->BooleanNot(),
      graph()->NewNode(simplified()->ReferenceEqual(), enum_indices,
                       jsgraph()->EmptyFixedArrayConstant()));
  effect = graph()->NewNode(
      simplified()->CheckIf(DeoptimizeReason::kWrongEnumIndices), check, effect,
      control);

  // Determine the key from the {enum_indices}.
  Node* key = effect = graph()->NewNode(
      simplified()->LoadElement(
          AccessBuilder::ForFixedArrayElement(PACKED_SMI_ELEMENTS)),
      enum_indices, index, effect, control);

  // Load the actual field value.
  Node* value = effect = graph()->NewNode(simplified()->LoadFieldByIndex(),
                                          receiver, key, effect, control);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSNativeContextSpecialization::ReduceJSLoadProperty(Node* node) {
  JSLoadPropertyNode n(node);
  PropertyAccess const& p = n.Parameters();
  Node* name = n.key();

  if (name->opcode() == IrOpcode::kJSForInNext) {
    Reduction reduction = ReduceJSLoadPropertyWithEnumeratedKey(node);
    if (reduction.Changed()) return reduction;
  }

  if (!p.feedback().IsValid()) return NoChange();
  Node* value = jsgraph()->Dead();
  return ReducePropertyAccess(node, name, std::nullopt, value,
                              FeedbackSource(p.feedback()), AccessMode::kLoad);
}

Reduction JSNativeContextSpecialization::ReduceJSSetKeyedProperty(Node* node) {
  JSSetKeyedPropertyNode n(node);
  PropertyAccess const& p = n.Parameters();
  if (!p.feedback().IsValid()) return NoChange();
  return ReducePropertyAccess(node, n.key(), std::nullopt, n.value(),
                              FeedbackSource(p.feedback()), AccessMode::kStore);
}

Reduction JSNativeContextSpecialization::ReduceJSDefineKeyedOwnProperty(
    Node* node) {
  JSDefineKeyedOwnPropertyNode n(node);
  PropertyAccess const& p = n.Parameters();
  if (!p.feedback().IsValid()) return NoChange();
  return ReducePropertyAccess(node, n.key(), std::nullopt, n.value(),
                              FeedbackSource(p.feedback()),
                              AccessMode::kDefine);
}

Node* JSNativeContextSpecialization::InlinePropertyGetterCall(
    Node* receiver, ConvertReceiverMode receiver_mode,
    Node* lookup_start_object, Node* context, Node* frame_state, Node** effect,
    Node** control, ZoneVector<Node*>* if_exceptions,
    PropertyAccessInfo const& access_info) {
  ObjectRef constant = access_info.constant().value();

  if (access_info.IsDictionaryProtoAccessorConstant()) {
    // For fast mode holders we recorded dependencies in BuildPropertyLoad.
    for (const MapRef map : access_info.lookup_start_object_maps()) {
      dependencies()->DependOnConstantInDictionaryPrototypeChain(
          map, access_info.name(), constant, PropertyKind::kAccessor);
    }
  }

  Node* target = jsgraph()->ConstantNoHole(constant, broker());
  // Introduce the call to the getter function.
  Node* value;
  if (constant.IsJSFunction()) {
    Node* feedback = jsgraph()->UndefinedConstant();
    value = *effect = *control = graph()->NewNode(
        jsgraph()->javascript()->Call(JSCallNode::ArityForArgc(0),
                                      CallFrequency(), FeedbackSource(),
                                      receiver_mode),
        target, receiver, feedback, context, frame_state, *effect, *control);
  } else {
    // Disable optimizations for super ICs using API getters, so that we get
    // the correct receiver checks.
    if (receiver != lookup_start_object) {
      return nullptr;
    }
    Node* api_holder = access_info.api_holder().has_value()
                           ? jsgraph()->ConstantNoHole(
                                 access_info.api_holder().value(), broker())
                           : receiver;
    value = InlineApiCall(receiver, api_holder, frame_state, nullptr, effect,
                          control, constant.AsFunctionTemplateInfo());
  }
  // Remember to rewire the IfException edge if this is inside a try-block.
  if (if_exceptions != nullptr) {
    // Create the appropriate IfException/IfSuccess projections.
    Node* const if_exception =
        graph()->NewNode(common()->IfException(), *control, *effect);
    Node* const if_success = graph()->NewNode(common()->IfSuccess(), *control);
    if_exceptions->push_back(if_exception);
    *control = if_success;
  }
  return value;
}

void JSNativeContextSpecialization::InlinePropertySetterCall(
    Node* receiver, Node* value, Node* context, Node* frame_state,
    Node** effect, Node** control, ZoneVector<Node*>* if_exceptions,
    PropertyAccessInfo const& access_info) {
  ObjectRef constant = access_info.constant().value();
  Node* target = jsgraph()->ConstantNoHole(constant, broker());
  // Introduce the call to the setter function.
  if (constant.IsJSFunction()) {
    Node* feedback = jsgraph()->UndefinedConstant();
    *effect = *control = graph()->NewNode(
        jsgraph()->javascript()->Call(JSCallNode::ArityForArgc(1),
                                      CallFrequency(), FeedbackSource(),
                                      ConvertReceiverMode::kNotNullOrUndefined),
        target, receiver, value, feedback, context, frame_state, *effect,
        *control);
  } else {
    Node* api_holder = access_info.api_holder().has_value()
                           ? jsgraph()->ConstantNoHole(
                                 access_info.api_holder().value(), broker())
                           : receiver;
    InlineApiCall(receiver, api_holder, frame_state, value, effect, control,
                  constant.AsFunctionTemplateInfo());
  }
  // Remember to rewire the IfException edge if this is inside a try-block.
  if (if_exceptions != nullptr) {
    // Create the appropriate IfException/IfSuccess projections.
    Node* const if_exception =
        graph()->NewNode(common()->IfException(), *control, *effect);
    Node* const if_success = graph()->NewNode(common()->IfSuccess(), *control);
    if_exceptions->push_back(if_exception);
    *control = if_success;
  }
}

Node* JSNativeContextSpecialization::InlineApiCall(
    Node* receiver, Node* api_holder, Node* frame_state, Node* value,
    Node** effect, Node** control,
    FunctionTemplateInfoRef function_template_info) {
  compiler::OptionalObjectRef maybe_callback_data =
      function_template_info.callback_data(broker());
  // Check if the function has an associated C++ code to execute.
  if (!maybe_callback_data.has_value()) {
    // TODO(ishell): consider generating "return undefined" for empty function
    // instead of failing.
    TRACE_BROKER_MISSING(broker(), "call code for function template info "
                                       << function_template_info);
    return nullptr;
  }

  // Only setters have a value.
  int const argc = value == nullptr ? 0 : 1;
  // The builtin always expects the receiver as the first param on the stack.
  bool no_profiling = broker()->dependencies()->DependOnNoProfilingProtector();
  Callable call_api_callback = Builtins::CallableFor(
      isolate(), no_profiling ? Builtin::kCallApiCallbackOptimizedNoProfiling
                              : Builtin::kCallApiCallbackOptimized);
  CallInterfaceDescriptor call_interface_descriptor =
      call_api_callback.descriptor();
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      graph()->zone(), call_interface_descriptor,
      call_interface_descriptor.GetStackParameterCount() + argc +
          1 /* implicit receiver */,
      CallDescriptor::kNeedsFrameState);

  Node* func_templ =
      jsgraph()->HeapConstantNoHole(function_template_info.object());
  ApiFunction function(function_template_info.callback(broker()));
  Node* function_reference =
      graph()->NewNode(common()->ExternalConstant(ExternalReference::Create(
          &function, ExternalReference::DIRECT_API_CALL)));
  Node* code = jsgraph()->HeapConstantNoHole(call_api_callback.code());

  // Add CallApiCallbackStub's register argument as well.
  Node* context = jsgraph()->ConstantNoHole(native_context(), broker());
  Node* inputs[11] = {
      code,       function_reference, jsgraph()->ConstantNoHole(argc),
      func_templ, api_holder,         receiver};
  int index = 6 + argc;
  inputs[index++] = context;
  inputs[index++] = frame_state;
  inputs[index++] = *effect;
  inputs[index++] = *control;
  // This needs to stay here because of the edge case described in
  // http://crbug.com/675648.
  if (value != nullptr) {
    inputs[6] = value;
  }

  return *effect = *control =
             graph()->NewNode(common()->Call(call_descriptor), index, inputs);
}

std::optional<JSNativeContextSpecialization::ValueEffectControl>
JSNativeContextSpecialization::BuildPropertyLoad(
    Node* lookup_start_object, Node* receiver, Node* context, Node* frame_state,
    Node* effect, Node* control, NameRef name, ZoneVector<Node*>* if_exceptions,
    PropertyAccessInfo const& access_info) {
  // Determine actual holder and perform prototype chain checks.
  OptionalJSObjectRef holder = access_info.holder();
  if (holder.has_value() && !access_info.HasDictionaryHolder()) {
    dependencies()->DependOnStablePrototypeChains(
        access_info.lookup_start_object_maps(), kStartAtPrototype,
        holder.value());
  }

  // Generate the actual property access.
  Node* value;
  if (access_info.IsNotFound()) {
    value = jsgraph()->UndefinedConstant();
  } else if (access_info.IsFastAccessorConstant() ||
             access_info.IsDictionaryProtoAccessorConstant()) {
    ConvertReceiverMode receiver_mode =
        receiver == lookup_start_object
            ? ConvertReceiverMode::kNotNullOrUndefined
            : ConvertReceiverMode::kAny;
    value = InlinePropertyGetterCall(
        receiver, receiver_mode, lookup_start_object, context, frame_state,
        &effect, &control, if_exceptions, access_info);
  } else if (access_info.IsModuleExport()) {
    Node* cell = jsgraph()->ConstantNoHole(
        access_info.constant().value().AsCell(), broker());
    value = effect =
        graph()->NewNode(simplified()->LoadField(AccessBuilder::ForCellValue()),
                         cell, effect, control);
  } else if (access_info.IsStringLength()) {
    DCHECK_EQ(receiver, lookup_start_object);
    value = graph()->NewNode(simplified()->StringLength(), receiver);
  } else if (access_info.IsStringWrapperLength()) {
    value = graph()->NewNode(simplified()->StringWrapperLength(),
                             lookup_start_object);
  } else {
    DCHECK(access_info.IsDataField() || access_info.IsFastDataConstant() ||
           access_info.IsDictionaryProtoDataConstant());
    PropertyAccessBuilder access_builder(jsgraph(), broker());
    if (access_info.IsDictionaryProtoDataConstant()) {
      auto maybe_value =
          access_builder.FoldLoadDictPrototypeConstant(access_info);
      if (!maybe_value) return {};
      value = maybe_value.value();
    } else {
      value = access_builder.BuildLoadDataField(
          name, access_info, lookup_start_object, &effect, &control);
    }
  }
  if (value != nullptr) {
    return ValueEffectControl(value, effect, control);
  }
  return std::optional<ValueEffectControl>();
}

JSNativeContextSpecialization::ValueEffectControl
JSNativeContextSpecialization::BuildPropertyTest(
    Node* effect,
"""


```