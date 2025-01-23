Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/js-native-context-specialization.cc`. The summary should also consider specific instructions about interpreting the filename extension as Torque code, relating the code to JavaScript, giving examples, and identifying common programming errors.

Here's a breakdown of the thinking process:

1. **Identify the core purpose:** The filename `js-native-context-specialization.cc` strongly suggests this code is about optimizing JavaScript code within V8, specifically focusing on the "native context."  The presence of `ReduceJS...` functions further confirms this, indicating optimization passes for different JavaScript operations.

2. **Analyze the `ReducePropertyAccess` function:** This function appears central to the code. It handles property access (both loading and storing). The logic involves:
    * Checking for constant receivers.
    * Utilizing feedback from the runtime to optimize based on observed object structures (maps).
    * Handling monomorphic (single structure) and polymorphic (multiple structures) cases.
    * Generating appropriate checks (e.g., `CheckMaps`, `CheckString`, `CheckNumber`) to ensure type safety and enable optimizations.
    * Building the actual property access operation.
    * Rewiring exception edges.

3. **Examine other `ReduceJS...` functions:** These functions appear to be wrappers around `ReducePropertyAccess` or handle specific cases:
    * `ReduceJSLoadNamed`: Handles loading named properties. Includes optimizations for "prototype" and "length" on constant objects.
    * `ReduceJSLoadNamedFromSuper`: Handles loading named properties from a superclass.
    * `ReduceJSGetIterator`:  Handles the `[Symbol.iterator]` lookup and call. This is more involved, including checks and potential runtime calls.
    * `ReduceJSSetNamedProperty`: Handles setting named properties.
    * `ReduceJSDefineNamedOwnProperty`: Handles defining own named properties.
    * `ReduceElementAccess`: Handles accessing properties using bracket notation (e.g., `obj[key]`). Includes specific logic for strings and typed arrays.
    * `ReduceElementAccessOnString`: Specializes element access for strings.

4. **Address the ".tq" instruction:** The prompt asks what would be different if the file ended in `.tq`. This refers to Torque, V8's domain-specific language for implementing built-in functions. If it were a `.tq` file, the code would be written in Torque syntax, likely generating C++ code similar to what's seen here. The core functionality would be the same, but the implementation language would differ.

5. **Relate to JavaScript with examples:**  For each major function, think of corresponding JavaScript code. For example:
    * `ReduceJSLoadNamed`: `object.property`
    * `ReduceJSSetNamedProperty`: `object.property = value`
    * `ReduceJSGetIterator`: `object[Symbol.iterator]()`
    * `ReduceElementAccess`: `object[index]`

6. **Consider code logic and assumptions:**  Focus on the `ReducePropertyAccess` function's handling of monomorphic and polymorphic cases. The assumption is that runtime feedback provides information about the likely structure of objects. The input would be a graph representation of a JavaScript operation, and the output would be a potentially optimized graph.

7. **Identify common programming errors:** Think about the kinds of errors that the optimizations in this code try to address or that could lead to deoptimization:
    * Accessing properties on `null` or `undefined`.
    * Assuming an object has a certain property when it doesn't.
    * Incorrectly using the prototype chain.
    * Mismatch between expected and actual object structure (leading to megamorphic access).

8. **Synthesize the summary:** Combine the information gathered in the previous steps to create a concise overview of the file's purpose and functionality, specifically addressing the user's instructions. Emphasize that the code optimizes JavaScript property access based on runtime feedback and type information.

9. **Review and refine:** Ensure the summary is clear, accurate, and addresses all parts of the prompt. Pay attention to phrasing and organization. For example, make sure the explanation of Torque is clear and concise.

By following this process, we can generate a comprehensive and accurate summary of the provided V8 source code.
好的，根据你提供的代码片段，以下是 `v8/src/compiler/js-native-context-specialization.cc` 文件第 3 部分的功能归纳：

**核心功能：优化 JavaScript 属性访问**

这部分代码的核心功能是优化 JavaScript 中属性的访问（包括读取和写入）。它利用类型反馈信息（`feedback`）和图（`graph`）中的类型推断来生成更高效的机器码。 主要处理 `JSLoadNamed`, `JSLoadNamedFromSuper`, `JSGetIterator`, `JSSetNamedProperty`, `JSDefineNamedOwnProperty` 和 `ReduceElementAccess` 等操作。

**具体功能点:**

1. **`ReducePropertyAccess(Node* node, Node* key, NameRef name, Node* value, const FeedbackSource& feedback, AccessMode access_mode)`:** 这是处理属性访问的核心函数。它的主要逻辑是：
    * **收集类型信息:** 根据 `feedback` 获取可能的对象类型（`inferred_maps`）。
    * **处理共享空间对象:**  对于存储操作，如果对象位于共享空间，则可能需要特殊处理（目前代码中看到有 TODO，可能暂不支持）。
    * **获取访问信息 (`PropertyAccessInfo`):**  利用 `broker()` 获取关于属性访问的详细信息，例如属性的位置、类型等。
    * **构建类型检查:**  根据 `access_infos` 中的信息，为 `lookup_start_object` 和 `receiver` 构建必要的类型检查，例如 `CheckMaps` (检查对象是否属于预期的 Map), `CheckString`, `CheckNumber` 等。
    * **处理 monomorphic 和 polymorphic 情况:**
        * **Monomorphic (单态):** 如果只有一个可能的对象类型，则直接构建高效的属性访问操作。
        * **Polymorphic (多态):** 如果有多个可能的对象类型，则为每种类型生成不同的代码分支，并在运行时根据对象的实际类型选择执行哪个分支。使用 `Merge` 和 `Phi` 节点来合并不同分支的结果。
    * **生成属性访问代码 (`BuildPropertyAccess`):**  调用 `BuildPropertyAccess` 函数生成实际的属性访问操作。
    * **处理异常:**  如果原始节点是可能抛出异常的调用，则会收集 `IfException` 节点，并在所有分支处理完成后重新连接异常边。

2. **`ReduceJSLoadNamed(Node* node)`:** 优化具名属性的加载，例如 `object.property`。
    * **常量折叠:** 对于常量接收者，例如字符串的 `length` 属性或函数的 `prototype` 属性，可以直接计算出结果，避免运行时查找。
    * **调用 `ReducePropertyAccess`:**  对于其他情况，调用 `ReducePropertyAccess` 来进行更通用的优化。

3. **`ReduceJSLoadNamedFromSuper(Node* node)`:** 优化从父类原型链上加载具名属性的操作，例如 `super.property`。
    * **调用 `ReducePropertyAccess`:** 直接调用 `ReducePropertyAccess` 进行优化。

4. **`ReduceJSGetIterator(Node* node)`:** 优化获取迭代器的方法调用，例如 `object[Symbol.iterator]()`。
    * **加载 `Symbol.iterator` 属性:**  首先加载对象的 `Symbol.iterator` 属性。
    * **检查是否为 undefined:** 如果是 `undefined`，则抛出 `TypeError`。
    * **调用迭代器方法:** 调用加载到的迭代器方法。
    * **检查返回值是否为对象:** 检查调用结果是否为 JSReceiver (Object)，如果不是则抛出 `TypeError`。
    * **处理异常:**  细致地处理了在加载属性和调用方法过程中可能产生的异常。

5. **`ReduceJSSetNamedProperty(Node* node)`:** 优化具名属性的设置，例如 `object.property = value`。
    * **调用 `ReducePropertyAccess`:** 调用 `ReducePropertyAccess` 来进行优化。

6. **`ReduceJSDefineNamedOwnProperty(Node* node)`:** 优化定义对象自身拥有的具名属性，例如 `Object.defineProperty(object, 'property', ...)`。
    * **调用 `ReducePropertyAccess`:** 调用 `ReducePropertyAccess` 来进行优化。

7. **`ReduceElementAccessOnString(Node* node, Node* index, Node* value, const KeyedAccessMode& keyed_mode)`:** 优化字符串的元素访问，例如 `string[index]`。
    * **只处理读取操作:** 字符串在 JavaScript 中是不可变的，所以只处理读取 (`AccessMode::kLoad`)。
    * **类型检查:** 确保接收者是字符串。
    * **获取字符串长度:** 获取字符串的长度。
    * **构建索引加载操作:**  调用 `BuildIndexedStringLoad` 根据索引加载字符。

8. **`ReduceElementAccess(Node* node, Node* index, Node* value, const ElementAccessFeedback& feedback)`:** 优化元素访问（通过方括号访问），例如 `array[index]` 或 `object[key]`。
    * **常量折叠 (部分):** 对于某些常量接收者，可以进行优化。
    * **字符串优化:** 如果类型反馈表明对象是字符串，则调用 `ReduceElementAccessOnString`。
    * **获取元素访问信息 (`ElementAccessInfo`):**  根据 `feedback` 计算可能的元素类型和存储方式。
    * **Typed Array 处理:**  对于 Typed Array，目前看到有针对 `AccessMode::kDefine` 和 `Float16` 的特殊处理，表明可能存在一些限制或未完成的优化。
    * **调用底层的元素访问构建函数 (未在此片段中展示):**  根据 `access_infos` 构建实际的元素访问操作。

**如果 `v8/src/compiler/js-native-context-specialization.cc` 以 `.tq` 结尾：**

如果文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。 Torque 是一种 V8 内部使用的领域特定语言，用于定义内置函数和一些优化的实现。 Torque 代码会被编译成 C++ 代码。

**与 JavaScript 功能的关系和示例：**

这部分代码直接对应于 JavaScript 中各种属性访问的语法和操作：

* **`object.property` (读取):** 对应 `ReduceJSLoadNamed`
  ```javascript
  const obj = { name: 'Alice' };
  const name = obj.name; // ReduceJSLoadNamed 会优化这个操作
  ```

* **`super.property` (读取):** 对应 `ReduceJSLoadNamedFromSuper`
  ```javascript
  class Parent {
    constructor() {
      this.parentProp = 'parent';
    }
  }
  class Child extends Parent {
    getChildProp() {
      return super.parentProp; // ReduceJSLoadNamedFromSuper 会优化这个操作
    }
  }
  ```

* **`object[Symbol.iterator]()`:** 对应 `ReduceJSGetIterator`
  ```javascript
  const arr = [1, 2, 3];
  const iterator = arr[Symbol.iterator](); // ReduceJSGetIterator 会优化这个操作
  ```

* **`object.property = value` (写入):** 对应 `ReduceJSSetNamedProperty`
  ```javascript
  const obj = {};
  obj.age = 30; // ReduceJSSetNamedProperty 会优化这个操作
  ```

* **`Object.defineProperty(object, 'property', ...)`:** 对应 `ReduceJSDefineNamedOwnProperty`
  ```javascript
  const obj = {};
  Object.defineProperty(obj, 'city', { value: 'New York', writable: true }); // ReduceJSDefineNamedOwnProperty 会优化这个操作
  ```

* **`string[index]`:** 对应 `ReduceElementAccessOnString` (以及 `ReduceElementAccess` 对于字符串的情况)
  ```javascript
  const str = "hello";
  const char = str[1]; // ReduceElementAccessOnString 会优化这个操作
  ```

* **`array[index]` 或 `object[key]`:** 对应 `ReduceElementAccess`
  ```javascript
  const arr = [10, 20, 30];
  const value = arr[0]; // ReduceElementAccess 会优化这个操作

  const obj = { key: 'value' };
  const val = obj['key']; // ReduceElementAccess 会优化这个操作
  ```

**代码逻辑推理的假设输入与输出：**

假设输入是一个表示 JavaScript 代码 `obj.name` 的中间表示（例如，一个 `JSLoadNamed` 节点），并且运行时反馈信息指示 `obj` 大概率是 `{ name: string }` 类型的对象。

**假设输入：**

* `node`: 指向 `JSLoadNamed` 节点的指针。
* `feedback`:  包含类型信息，指示接收者 `obj` 的 Map 是指向具有字符串类型 `name` 属性的对象的 Map。
* `receiver`: 指向表示 `obj` 的节点的指针。
* `name`:  `NameRef` 指向字符串 "name"。

**可能的输出（经过优化）：**

* 代码会插入 `CheckMaps` 节点，用于在运行时快速检查 `obj` 的 Map 是否与反馈信息中的 Map 一致。
* 如果 Map 匹配，则会生成直接读取该属性的指令，而无需进行更耗时的通用属性查找。
* `JSLoadNamed` 节点会被替换为直接读取属性值的操作。

**涉及用户常见的编程错误：**

这部分代码的优化旨在提高性能，但也间接处理了一些常见的编程错误，或者在出现这些错误时可能会导致优化失效（deoptimization）：

1. **访问 `null` 或 `undefined` 的属性:** 例如 `null.name`。虽然这里的代码本身不直接阻止这种错误，但类型检查和反馈机制可能会识别出这种模式，并避免进行过于激进的优化，因为这种操作通常会导致运行时错误。

2. **假设对象具有某个属性，但实际上没有:** 例如，期望 `obj.name` 存在，但 `obj` 可能是一个空对象。  类型反馈会帮助优化器了解属性的实际存在情况，但如果反馈不准确或对象结构变化，可能会导致 deoptimization。

3. **原型链上的属性访问导致的性能问题:**  通过缓存和优化 Map 信息，可以加速原型链上的属性查找。

4. **意外的类型变化导致的性能下降:** 例如，最初一个对象总是拥有某个类型的属性，优化器据此进行了优化，但之后该属性的类型发生了变化。 这会导致类型检查失败，触发 deoptimization。

**总结一下它的功能:**

这段 `v8/src/compiler/js-native-context-specialization.cc` 的代码主要负责 **基于类型反馈信息和静态分析，优化 JavaScript 中各种形式的属性访问操作，包括具名属性和索引属性的读取、写入和定义。**  它针对不同的属性访问场景，例如普通属性访问、原型链访问、字符串元素访问以及 Typed Array 的元素访问，采取不同的优化策略，旨在生成更高效的机器码，提升 JavaScript 的执行性能。 核心是通过构建类型检查和利用反馈信息，避免运行时的通用属性查找，从而加速代码执行。

### 提示词
```
这是目录为v8/src/compiler/js-native-context-specialization.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-native-context-specialization.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
,
                                  effect);
      }
    }
  }

  ZoneVector<PropertyAccessInfo> access_infos(zone());
  {
    ZoneVector<PropertyAccessInfo> access_infos_for_feedback(zone());
    for (MapRef map : inferred_maps) {
      if (map.is_deprecated()) continue;

      // TODO(v8:12547): Support writing to objects in shared space, which need
      // a write barrier that calls Object::Share to ensure the RHS is shared.
      if (InstanceTypeChecker::IsAlwaysSharedSpaceJSObject(
              map.instance_type()) &&
          access_mode == AccessMode::kStore) {
        return NoChange();
      }

      PropertyAccessInfo access_info =
          broker()->GetPropertyAccessInfo(map, feedback.name(), access_mode);
      access_infos_for_feedback.push_back(access_info);
    }

    AccessInfoFactory access_info_factory(broker(), graph()->zone());
    if (!access_info_factory.FinalizePropertyAccessInfos(
            access_infos_for_feedback, access_mode, &access_infos)) {
      return NoChange();
    }
  }

  // Ensure that {key} matches the specified name (if {key} is given).
  if (key != nullptr) {
    effect = BuildCheckEqualsName(feedback.name(), key, effect, control);
  }

  // Collect call nodes to rewire exception edges.
  ZoneVector<Node*> if_exception_nodes(zone());
  ZoneVector<Node*>* if_exceptions = nullptr;
  Node* if_exception = nullptr;
  if (NodeProperties::IsExceptionalCall(node, &if_exception)) {
    if_exceptions = &if_exception_nodes;
  }

  PropertyAccessBuilder access_builder(jsgraph(), broker());

  // Check for the monomorphic cases.
  if (access_infos.size() == 1) {
    PropertyAccessInfo access_info = access_infos.front();
    if (receiver != lookup_start_object) {
      // Super property access. lookup_start_object is a JSReceiver or
      // null. It can't be a number, a string etc. So trying to build the
      // checks in the "else if" branch doesn't make sense.

      access_builder.BuildCheckMaps(lookup_start_object, &effect, control,
                                    access_info.lookup_start_object_maps());

      if (HasOnlyStringWrapperMaps(broker(),
                                   access_info.lookup_start_object_maps())) {
        // In order to be able to use StringWrapperLength, we need a TypeGuard
        // when all input maps are StringWrapper maps.
        lookup_start_object = effect =
            graph()->NewNode(common()->TypeGuard(Type::StringWrapper()),
                             lookup_start_object, effect, control);
      }

    } else if (!access_builder.TryBuildStringCheck(
                   broker(), access_info.lookup_start_object_maps(), &receiver,
                   &effect, control) &&
               !access_builder.TryBuildNumberCheck(
                   broker(), access_info.lookup_start_object_maps(), &receiver,
                   &effect, control)) {
      // Try to build string check or number check if possible. Otherwise build
      // a map check.

      // TryBuildStringCheck and TryBuildNumberCheck don't update the receiver
      // if they fail.
      DCHECK_EQ(receiver, lookup_start_object);
      if (HasNumberMaps(broker(), access_info.lookup_start_object_maps())) {
        // We need to also let Smi {receiver}s through in this case, so
        // we construct a diamond, guarded by the Sminess of the {receiver}
        // and if {receiver} is not a Smi just emit a sequence of map checks.
        Node* check = graph()->NewNode(simplified()->ObjectIsSmi(), receiver);
        Node* branch = graph()->NewNode(common()->Branch(), check, control);

        Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
        Node* etrue = effect;

        Control if_false{graph()->NewNode(common()->IfFalse(), branch)};
        Effect efalse = effect;
        access_builder.BuildCheckMaps(receiver, &efalse, if_false,
                                      access_info.lookup_start_object_maps());

        control = graph()->NewNode(common()->Merge(2), if_true, if_false);
        effect =
            graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
      } else {
        access_builder.BuildCheckMaps(receiver, &effect, control,
                                      access_info.lookup_start_object_maps());
      }

      if (HasOnlyStringWrapperMaps(broker(),
                                   access_info.lookup_start_object_maps())) {
        // In order to be able to use StringWrapperLength, we need a TypeGuard
        // when all input maps are StringWrapper maps. Note that, alternatively,
        // we could have a CheckStringWrapper, but it makes things simpler to
        // just rely on CheckMaps. This is slightly suboptimal in case the code
        // contains multiple string wrappers with different properties, but this
        // should be a rare case.
        lookup_start_object = receiver = effect =
            graph()->NewNode(common()->TypeGuard(Type::StringWrapper()),
                             lookup_start_object, effect, control);
      }
    } else {
      // At least one of TryBuildStringCheck & TryBuildNumberCheck succeeded
      // and updated the receiver. Update lookup_start_object to match (they
      // should be the same).
      lookup_start_object = receiver;
    }

    // Generate the actual property access.
    std::optional<ValueEffectControl> continuation = BuildPropertyAccess(
        lookup_start_object, receiver, value, context, frame_state, effect,
        control, feedback.name(), if_exceptions, access_info, access_mode);
    if (!continuation) {
      // At this point we maybe have added nodes into the graph (e.g. via
      // NewNode or BuildCheckMaps) in some cases but we haven't connected them
      // to End since we haven't called ReplaceWithValue. Since they are nodes
      // which are not connected with End, they will be removed by graph
      // trimming.
      return NoChange();
    }
    value = continuation->value();
    effect = continuation->effect();
    control = continuation->control();
  } else {
    // The final states for every polymorphic branch. We join them with
    // Merge+Phi+EffectPhi at the bottom.
    ZoneVector<Node*> values(zone());
    ZoneVector<Node*> effects(zone());
    ZoneVector<Node*> controls(zone());

    Node* receiverissmi_control = nullptr;
    Node* receiverissmi_effect = effect;

    if (receiver == lookup_start_object) {
      // Check if {receiver} may be a number.
      bool receiverissmi_possible = false;
      for (PropertyAccessInfo const& access_info : access_infos) {
        if (HasNumberMaps(broker(), access_info.lookup_start_object_maps())) {
          receiverissmi_possible = true;
          break;
        }
      }

      // Handle the case that {receiver} may be a number.
      if (receiverissmi_possible) {
        Node* check = graph()->NewNode(simplified()->ObjectIsSmi(), receiver);
        Node* branch = graph()->NewNode(common()->Branch(), check, control);
        control = graph()->NewNode(common()->IfFalse(), branch);
        receiverissmi_control = graph()->NewNode(common()->IfTrue(), branch);
        receiverissmi_effect = effect;
      }
    }

    // Generate code for the various different property access patterns.
    Node* fallthrough_control = control;
    for (size_t j = 0; j < access_infos.size(); ++j) {
      PropertyAccessInfo const& access_info = access_infos[j];
      Node* this_value = value;
      Node* this_lookup_start_object = lookup_start_object;
      Node* this_receiver = receiver;
      Effect this_effect = effect;
      Control this_control{fallthrough_control};

      // Perform map check on {lookup_start_object}.
      ZoneVector<MapRef> const& lookup_start_object_maps =
          access_info.lookup_start_object_maps();
      {
        // Whether to insert a dedicated MapGuard node into the
        // effect to be able to learn from the control flow.
        bool insert_map_guard = true;

        // Check maps for the {lookup_start_object}s.
        if (j == access_infos.size() - 1) {
          // Last map check on the fallthrough control path, do a
          // conditional eager deoptimization exit here.
          access_builder.BuildCheckMaps(lookup_start_object, &this_effect,
                                        this_control, lookup_start_object_maps);
          fallthrough_control = nullptr;

          // Don't insert a MapGuard in this case, as the CheckMaps
          // node already gives you all the information you need
          // along the effect chain.
          insert_map_guard = false;
        } else {
          // Explicitly branch on the {lookup_start_object_maps}.
          ZoneRefSet<Map> maps(lookup_start_object_maps.begin(),
                               lookup_start_object_maps.end(), graph()->zone());
          Node* check = this_effect =
              graph()->NewNode(simplified()->CompareMaps(maps),
                               lookup_start_object, this_effect, this_control);
          Node* branch =
              graph()->NewNode(common()->Branch(), check, this_control);
          fallthrough_control = graph()->NewNode(common()->IfFalse(), branch);
          this_control = graph()->NewNode(common()->IfTrue(), branch);
        }

        // The Number case requires special treatment to also deal with Smis.
        if (HasNumberMaps(broker(), lookup_start_object_maps)) {
          // Join this check with the "receiver is smi" check above.
          DCHECK_EQ(receiver, lookup_start_object);
          DCHECK_NOT_NULL(receiverissmi_effect);
          DCHECK_NOT_NULL(receiverissmi_control);
          this_control = graph()->NewNode(common()->Merge(2), this_control,
                                          receiverissmi_control);
          this_effect = graph()->NewNode(common()->EffectPhi(2), this_effect,
                                         receiverissmi_effect, this_control);
          receiverissmi_effect = receiverissmi_control = nullptr;

          // The {lookup_start_object} can also be a Smi in this case, so
          // a MapGuard doesn't make sense for this at all.
          insert_map_guard = false;
        }

        // Introduce a MapGuard to learn from this on the effect chain.
        if (insert_map_guard) {
          ZoneRefSet<Map> maps(lookup_start_object_maps.begin(),
                               lookup_start_object_maps.end(), graph()->zone());
          this_effect =
              graph()->NewNode(simplified()->MapGuard(maps),
                               lookup_start_object, this_effect, this_control);
        }

        // If all {lookup_start_object_maps} are Strings we also need to rename
        // the {lookup_start_object} here to make sure that TurboFan knows that
        // along this path the {this_lookup_start_object} is a String. This is
        // because we want strict checking of types, for example for
        // StringLength operators.
        if (HasOnlyStringMaps(broker(), lookup_start_object_maps)) {
          DCHECK_EQ(receiver, lookup_start_object);
          this_lookup_start_object = this_receiver = this_effect =
              graph()->NewNode(common()->TypeGuard(Type::String()),
                               lookup_start_object, this_effect, this_control);
        } else if (HasOnlyStringWrapperMaps(broker(),
                                            lookup_start_object_maps)) {
          bool receiver_is_lookup_start =
              this_lookup_start_object == this_receiver;
          DCHECK_IMPLIES(access_mode != AccessMode::kLoad,
                         receiver_is_lookup_start);
          this_lookup_start_object = this_effect =
              graph()->NewNode(common()->TypeGuard(Type::StringWrapper()),
                               lookup_start_object, this_effect, this_control);
          if (receiver_is_lookup_start) {
            this_receiver = this_lookup_start_object;
          }
        }
      }

      // Generate the actual property access.
      std::optional<ValueEffectControl> continuation = BuildPropertyAccess(
          this_lookup_start_object, this_receiver, this_value, context,
          frame_state, this_effect, this_control, feedback.name(),
          if_exceptions, access_info, access_mode);
      if (!continuation) {
        // At this point we maybe have added nodes into the graph (e.g. via
        // NewNode or BuildCheckMaps) in some cases but we haven't connected
        // them to End since we haven't called ReplaceWithValue. Since they are
        // nodes which are not connected with End, they will be removed by graph
        // trimming.
        return NoChange();
      }

      values.push_back(continuation->value());
      effects.push_back(continuation->effect());
      controls.push_back(continuation->control());
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

  // Properly rewire IfException edges if {node} is inside a try-block.
  if (!if_exception_nodes.empty()) {
    DCHECK_NOT_NULL(if_exception);
    DCHECK_EQ(if_exceptions, &if_exception_nodes);
    int const if_exception_count = static_cast<int>(if_exceptions->size());
    Node* merge = graph()->NewNode(common()->Merge(if_exception_count),
                                   if_exception_count, &if_exceptions->front());
    if_exceptions->push_back(merge);
    Node* ephi =
        graph()->NewNode(common()->EffectPhi(if_exception_count),
                         if_exception_count + 1, &if_exceptions->front());
    Node* phi = graph()->NewNode(
        common()->Phi(MachineRepresentation::kTagged, if_exception_count),
        if_exception_count + 1, &if_exceptions->front());
    ReplaceWithValue(if_exception, phi, ephi, merge);
  }

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSNativeContextSpecialization::ReduceJSLoadNamed(Node* node) {
  JSLoadNamedNode n(node);
  NamedAccess const& p = n.Parameters();
  Node* const receiver = n.object();
  NameRef name = p.name();

  // Check if we have a constant receiver.
  HeapObjectMatcher m(receiver);
  if (m.HasResolvedValue()) {
    ObjectRef object = m.Ref(broker());
    if (object.IsJSFunction() && name.equals(broker()->prototype_string())) {
      // Optimize "prototype" property of functions.
      JSFunctionRef function = object.AsJSFunction();
      // TODO(neis): Remove the has_prototype_slot condition once the broker is
      // always enabled.
      if (!function.map(broker()).has_prototype_slot() ||
          !function.has_instance_prototype(broker()) ||
          function.PrototypeRequiresRuntimeLookup(broker())) {
        return NoChange();
      }
      HeapObjectRef prototype =
          dependencies()->DependOnPrototypeProperty(function);
      Node* value = jsgraph()->ConstantNoHole(prototype, broker());
      ReplaceWithValue(node, value);
      return Replace(value);
    } else if (object.IsString() && name.equals(broker()->length_string())) {
      // Constant-fold "length" property on constant strings.
      Node* value = jsgraph()->ConstantNoHole(object.AsString().length());
      ReplaceWithValue(node, value);
      return Replace(value);
    }
  }

  if (!p.feedback().IsValid()) return NoChange();
  return ReducePropertyAccess(node, nullptr, name, jsgraph()->Dead(),
                              FeedbackSource(p.feedback()), AccessMode::kLoad);
}

Reduction JSNativeContextSpecialization::ReduceJSLoadNamedFromSuper(
    Node* node) {
  JSLoadNamedFromSuperNode n(node);
  NamedAccess const& p = n.Parameters();
  NameRef name = p.name();

  if (!p.feedback().IsValid()) return NoChange();
  return ReducePropertyAccess(node, nullptr, name, jsgraph()->Dead(),
                              FeedbackSource(p.feedback()), AccessMode::kLoad);
}

Reduction JSNativeContextSpecialization::ReduceJSGetIterator(Node* node) {
  JSGetIteratorNode n(node);
  GetIteratorParameters const& p = n.Parameters();

  TNode<Object> receiver = n.receiver();
  TNode<Object> context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  Node* iterator_exception_node = nullptr;
  Node* if_exception_merge = nullptr;
  Node* if_exception_effect_phi = nullptr;
  Node* if_exception_phi = nullptr;
  bool has_exception_node =
      NodeProperties::IsExceptionalCall(node, &iterator_exception_node);
  int exception_node_index = 0;
  if (has_exception_node) {
    DCHECK_NOT_NULL(iterator_exception_node);
    // If there exists an IfException node for the iterator node, we need
    // to merge all the desugared nodes exception. The iterator node will be
    // desugared to LoadNamed, Call, CallRuntime, we can pre-allocate the
    // nodes with 4 inputs here and we use dead_node as a placeholder for the
    // input, which will be replaced.
    // We use dead_node as a placeholder for the original exception node before
    // it's uses are rewired.

    Node* dead_node = jsgraph()->Dead();
    if_exception_merge =
        graph()->NewNode(common()->Merge(5), dead_node, dead_node, dead_node,
                         dead_node, dead_node);
    if_exception_effect_phi =
        graph()->NewNode(common()->EffectPhi(5), dead_node, dead_node,
                         dead_node, dead_node, dead_node, if_exception_merge);
    if_exception_phi = graph()->NewNode(
        common()->Phi(MachineRepresentation::kTagged, 5), dead_node, dead_node,
        dead_node, dead_node, dead_node, if_exception_merge);
    // Rewire the original exception node uses.
    ReplaceWithValue(iterator_exception_node, if_exception_phi,
                     if_exception_effect_phi, if_exception_merge);
    if_exception_merge->ReplaceInput(exception_node_index,
                                     iterator_exception_node);
    if_exception_effect_phi->ReplaceInput(exception_node_index,
                                          iterator_exception_node);
    if_exception_phi->ReplaceInput(exception_node_index,
                                   iterator_exception_node);
    exception_node_index++;
  }

  // Load iterator property operator
  NameRef iterator_symbol = broker()->iterator_symbol();
  const Operator* load_op =
      javascript()->LoadNamed(iterator_symbol, p.loadFeedback());

  // Lazy deopt of the load iterator property
  // TODO(v8:10047): Use TaggedIndexConstant here once deoptimizer supports it.
  Node* call_slot = jsgraph()->SmiConstant(p.callFeedback().slot.ToInt());
  Node* call_feedback = jsgraph()->HeapConstantNoHole(p.callFeedback().vector);
  Node* lazy_deopt_parameters[] = {receiver, call_slot, call_feedback};
  Node* lazy_deopt_frame_state = CreateStubBuiltinContinuationFrameState(
      jsgraph(), Builtin::kGetIteratorWithFeedbackLazyDeoptContinuation,
      context, lazy_deopt_parameters, arraysize(lazy_deopt_parameters),
      frame_state, ContinuationFrameStateMode::LAZY);
  Node* load_property =
      graph()->NewNode(load_op, receiver, n.feedback_vector(), context,
                       lazy_deopt_frame_state, effect, control);
  effect = load_property;
  control = load_property;

  // Merge the exception path for LoadNamed.
  if (has_exception_node) {
    Node* if_exception =
        graph()->NewNode(common()->IfException(), effect, control);
    if_exception_merge->ReplaceInput(exception_node_index, if_exception);
    if_exception_phi->ReplaceInput(exception_node_index, if_exception);
    if_exception_effect_phi->ReplaceInput(exception_node_index, if_exception);
    exception_node_index++;
    control = graph()->NewNode(common()->IfSuccess(), control);
  }

  Node* check = graph()->NewNode(simplified()->ReferenceEqual(), load_property,
                                 jsgraph()->UndefinedConstant());
  Node* branch =
      graph()->NewNode(common()->Branch(BranchHint::kFalse), check, control);

  {
    Node* if_not_iterator = graph()->NewNode(common()->IfTrue(), branch);
    Node* effect_not_iterator = effect;
    Node* control_not_iterator = if_not_iterator;
    Node* call_runtime = effect_not_iterator = control_not_iterator =
        graph()->NewNode(
            javascript()->CallRuntime(Runtime::kThrowIteratorError, 1),
            receiver, context, frame_state, effect_not_iterator,
            control_not_iterator);
    // Merge the exception path for CallRuntime.
    if (has_exception_node) {
      Node* if_exception = graph()->NewNode(
          common()->IfException(), effect_not_iterator, control_not_iterator);
      if_exception_merge->ReplaceInput(exception_node_index, if_exception);
      if_exception_phi->ReplaceInput(exception_node_index, if_exception);
      if_exception_effect_phi->ReplaceInput(exception_node_index, if_exception);
      exception_node_index++;
      control_not_iterator =
          graph()->NewNode(common()->IfSuccess(), control_not_iterator);
    }
    Node* throw_node =
        graph()->NewNode(common()->Throw(), call_runtime, control_not_iterator);
    MergeControlToEnd(graph(), common(), throw_node);
  }

  control = graph()->NewNode(common()->IfFalse(), branch);

  // Eager deopt of call iterator property
  Node* parameters[] = {receiver, load_property, call_slot, call_feedback};
  Node* eager_deopt_frame_state = CreateStubBuiltinContinuationFrameState(
      jsgraph(), Builtin::kCallIteratorWithFeedback, context, parameters,
      arraysize(parameters), frame_state, ContinuationFrameStateMode::EAGER);
  Node* deopt_checkpoint = graph()->NewNode(
      common()->Checkpoint(), eager_deopt_frame_state, effect, control);
  effect = deopt_checkpoint;

  // Call iterator property operator
  ProcessedFeedback const& feedback =
      broker()->GetFeedbackForCall(p.callFeedback());
  SpeculationMode mode = feedback.IsInsufficient()
                             ? SpeculationMode::kDisallowSpeculation
                             : feedback.AsCall().speculation_mode();
  const Operator* call_op = javascript()->Call(
      JSCallNode::ArityForArgc(0), CallFrequency(), p.callFeedback(),
      ConvertReceiverMode::kNotNullOrUndefined, mode,
      CallFeedbackRelation::kTarget);
  // Lazy deopt to check the call result is JSReceiver.
  Node* call_lazy_deopt_frame_state = CreateStubBuiltinContinuationFrameState(
      jsgraph(), Builtin::kCallIteratorWithFeedbackLazyDeoptContinuation,
      context, nullptr, 0, frame_state, ContinuationFrameStateMode::LAZY);
  Node* call_property = effect = control =
      graph()->NewNode(call_op, load_property, receiver, n.feedback_vector(),
                       context, call_lazy_deopt_frame_state, effect, control);

  // Merge the exception path for Call.
  if (has_exception_node) {
    Node* if_exception =
        graph()->NewNode(common()->IfException(), effect, control);
    if_exception_merge->ReplaceInput(exception_node_index, if_exception);
    if_exception_phi->ReplaceInput(exception_node_index, if_exception);
    if_exception_effect_phi->ReplaceInput(exception_node_index, if_exception);
    exception_node_index++;
    control = graph()->NewNode(common()->IfSuccess(), control);
  }

  // If the result is not JSReceiver, throw invalid iterator exception.
  Node* is_receiver =
      graph()->NewNode(simplified()->ObjectIsReceiver(), call_property);
  Node* branch_node = graph()->NewNode(common()->Branch(BranchHint::kTrue),
                                       is_receiver, control);
  {
    Node* if_not_receiver = graph()->NewNode(common()->IfFalse(), branch_node);
    Node* effect_not_receiver = effect;
    Node* control_not_receiver = if_not_receiver;
    Node* call_runtime = effect_not_receiver = control_not_receiver =
        graph()->NewNode(
            javascript()->CallRuntime(Runtime::kThrowSymbolIteratorInvalid, 0),
            context, frame_state, effect_not_receiver, control_not_receiver);
    // Merge the exception path for CallRuntime.
    if (has_exception_node) {
      Node* if_exception = graph()->NewNode(
          common()->IfException(), effect_not_receiver, control_not_receiver);
      if_exception_merge->ReplaceInput(exception_node_index, if_exception);
      if_exception_phi->ReplaceInput(exception_node_index, if_exception);
      if_exception_effect_phi->ReplaceInput(exception_node_index, if_exception);
      exception_node_index++;
      control_not_receiver =
          graph()->NewNode(common()->IfSuccess(), control_not_receiver);
    }
    Node* throw_node =
        graph()->NewNode(common()->Throw(), call_runtime, control_not_receiver);
    MergeControlToEnd(graph(), common(), throw_node);
  }
  Node* if_receiver = graph()->NewNode(common()->IfTrue(), branch_node);
  ReplaceWithValue(node, call_property, effect, if_receiver);

  if (has_exception_node) {
    DCHECK_EQ(exception_node_index, if_exception_merge->InputCount());
    DCHECK_EQ(exception_node_index, if_exception_effect_phi->InputCount() - 1);
    DCHECK_EQ(exception_node_index, if_exception_phi->InputCount() - 1);
#ifdef DEBUG
    for (Node* input : if_exception_merge->inputs()) {
      DCHECK(!input->IsDead());
    }
    for (Node* input : if_exception_effect_phi->inputs()) {
      DCHECK(!input->IsDead());
    }
    for (Node* input : if_exception_phi->inputs()) {
      DCHECK(!input->IsDead());
    }
#endif
  }
  return Replace(if_receiver);
}

Reduction JSNativeContextSpecialization::ReduceJSSetNamedProperty(Node* node) {
  JSSetNamedPropertyNode n(node);
  NamedAccess const& p = n.Parameters();
  if (!p.feedback().IsValid()) return NoChange();
  return ReducePropertyAccess(node, nullptr, p.name(), n.value(),
                              FeedbackSource(p.feedback()), AccessMode::kStore);
}

Reduction JSNativeContextSpecialization::ReduceJSDefineNamedOwnProperty(
    Node* node) {
  JSDefineNamedOwnPropertyNode n(node);
  DefineNamedOwnPropertyParameters const& p = n.Parameters();
  if (!p.feedback().IsValid()) return NoChange();
  return ReducePropertyAccess(node, nullptr, p.name(), n.value(),
                              FeedbackSource(p.feedback()),
                              AccessMode::kStoreInLiteral);
}

Reduction JSNativeContextSpecialization::ReduceElementAccessOnString(
    Node* node, Node* index, Node* value, KeyedAccessMode const& keyed_mode) {
  Node* receiver = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  // Strings are immutable in JavaScript.
  if (keyed_mode.access_mode() == AccessMode::kStore) return NoChange();

  // `in` cannot be used on strings.
  if (keyed_mode.access_mode() == AccessMode::kHas) return NoChange();

  // Ensure that the {receiver} is actually a String.
  receiver = effect = graph()->NewNode(
      simplified()->CheckString(FeedbackSource()), receiver, effect, control);

  // Determine the {receiver} length.
  Node* length = graph()->NewNode(simplified()->StringLength(), receiver);

  // Load the single character string from {receiver} or yield undefined
  // if the {index} is out of bounds (depending on the {load_mode}).
  value = BuildIndexedStringLoad(receiver, index, length, &effect, &control,
                                 keyed_mode.load_mode());

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

namespace {

OptionalJSTypedArrayRef GetTypedArrayConstant(JSHeapBroker* broker,
                                              Node* receiver) {
  HeapObjectMatcher m(receiver);
  if (!m.HasResolvedValue()) return std::nullopt;
  ObjectRef object = m.Ref(broker);
  if (!object.IsJSTypedArray()) return std::nullopt;
  JSTypedArrayRef typed_array = object.AsJSTypedArray();
  if (typed_array.is_on_heap()) return std::nullopt;
  return typed_array;
}

}  // namespace

void JSNativeContextSpecialization::RemoveImpossibleMaps(
    Node* object, ZoneVector<MapRef>* maps) const {
  OptionalMapRef root_map = InferRootMap(object);
  if (root_map.has_value() && !root_map->is_abandoned_prototype_map()) {
    maps->erase(
        std::remove_if(maps->begin(), maps->end(),
                       [root_map, this](MapRef map) {
                         return map.is_abandoned_prototype_map() ||
                                !map.FindRootMap(broker()).equals(*root_map);
                       }),
        maps->end());
  }
}

// Possibly refine the feedback using inferred map information from the graph.
ElementAccessFeedback const&
JSNativeContextSpecialization::TryRefineElementAccessFeedback(
    ElementAccessFeedback const& feedback, Node* receiver,
    Effect effect) const {
  AccessMode access_mode = feedback.keyed_mode().access_mode();
  bool use_inference =
      access_mode == AccessMode::kLoad || access_mode == AccessMode::kHas;
  if (!use_inference) return feedback;

  ZoneVector<MapRef> inferred_maps(zone());
  if (!InferMaps(receiver, effect, &inferred_maps)) return feedback;

  RemoveImpossibleMaps(receiver, &inferred_maps);
  // TODO(neis): After Refine, the resulting feedback can still contain
  // impossible maps when a target is kept only because more than one of its
  // sources was inferred. Think of a way to completely rule out impossible
  // maps.
  return feedback.Refine(broker(), inferred_maps);
}

Reduction JSNativeContextSpecialization::ReduceElementAccess(
    Node* node, Node* index, Node* value,
    ElementAccessFeedback const& feedback) {
  DCHECK(node->opcode() == IrOpcode::kJSLoadProperty ||
         node->opcode() == IrOpcode::kJSSetKeyedProperty ||
         node->opcode() == IrOpcode::kJSStoreInArrayLiteral ||
         node->opcode() == IrOpcode::kJSDefineKeyedOwnPropertyInLiteral ||
         node->opcode() == IrOpcode::kJSHasProperty ||
         node->opcode() == IrOpcode::kJSDefineKeyedOwnProperty);
  static_assert(JSLoadPropertyNode::ObjectIndex() == 0 &&
                JSSetKeyedPropertyNode::ObjectIndex() == 0 &&
                JSStoreInArrayLiteralNode::ArrayIndex() == 0 &&
                JSDefineKeyedOwnPropertyInLiteralNode::ObjectIndex() == 0 &&
                JSHasPropertyNode::ObjectIndex() == 0);

  Node* receiver = NodeProperties::GetValueInput(node, 0);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};
  Node* context = NodeProperties::GetContextInput(node);

  // TODO(neis): It's odd that we do optimizations below that don't really care
  // about the feedback, but we don't do them when the feedback is megamorphic.
  if (feedback.transition_groups().empty()) return NoChange();

  ElementAccessFeedback const& refined_feedback =
      TryRefineElementAccessFeedback(feedback, receiver, effect);

  AccessMode access_mode = refined_feedback.keyed_mode().access_mode();
  if ((access_mode == AccessMode::kLoad || access_mode == AccessMode::kHas) &&
      receiver->opcode() == IrOpcode::kHeapConstant) {
    Reduction reduction = ReduceElementLoadFromHeapConstant(
        node, index, access_mode, refined_feedback.keyed_mode().load_mode());
    if (reduction.Changed()) return reduction;
  }

  if (!refined_feedback.transition_groups().empty() &&
      refined_feedback.HasOnlyStringMaps(broker())) {
    return ReduceElementAccessOnString(node, index, value,
                                       refined_feedback.keyed_mode());
  }

  AccessInfoFactory access_info_factory(broker(), graph()->zone());
  ZoneVector<ElementAccessInfo> access_infos(zone());
  if (!access_info_factory.ComputeElementAccessInfos(refined_feedback,
                                                     &access_infos) ||
      access_infos.empty()) {
    return NoChange();
  }

  // Do not optimize AccessMode::kDefine for typed arrays.
  if (access_mode == AccessMode::kDefine) {
    for (const ElementAccessInfo& access_info : access_infos) {
      if (IsTypedArrayOrRabGsabTypedArrayElementsKind(
              access_info.elements_kind())) {
        return NoChange();
      }
    }
  }

  // Do not optimize Float16 typed arrays, since they are not yet supported by
  // the rest o
```