Response:
Let's break down the thought process for analyzing this V8 code snippet.

1. **Understanding the Request:** The request asks for the functionality of the given C++ code, its relation to JavaScript, potential errors, and a summary, keeping in mind it's part 9 of 18.

2. **Initial Scan and Keywords:** I'll first skim the code for recognizable keywords and patterns. Terms like `MaglevGraphBuilder`, `ReduceResult`, `TryBuildPropertyLoad`, `feedback`, `generic_access`, `known_node_aspects`, `RecordKnownProperty`, `TryReuseKnownPropertyLoad`, `BuildLoadStringLength`, `TryBuildLoadNamedProperty`, `VisitGetNamedProperty`, `Constant`, `VisitGetNamedPropertyFromSuper`, `BuildGetKeyedProperty`, `VisitGetKeyedProperty`, `VisitLdaModuleVariable`, `VisitStaModuleVariable`, `BuildLoadGlobal`, `VisitSetNamedProperty`, `VisitDefineNamedOwnProperty`, `VisitSetKeyedProperty`, `VisitDefineKeyedOwnProperty`, `VisitStaInArrayLiteral`, `VisitDefineKeyedOwnPropertyInLiteral`, and various `Visit` methods for arithmetic and logical operations immediately stand out. These suggest this code is involved in building a graph-based intermediate representation (Maglev) for JavaScript code, handling property access, global variable access, and basic operations.

3. **Identifying Core Functionality Blocks:** I'll group related sections of the code based on their purpose.

    * **Property Access (Loads and Stores):**  Sections involving `TryBuildPropertyLoad`, `TryBuildNamedAccess`, `TryReuseKnownPropertyLoad`, `RecordKnownProperty`, `TryBuildLoadNamedProperty`, `VisitGetNamedProperty`, `VisitGetNamedPropertyFromSuper`, `BuildGetKeyedProperty`, `VisitGetKeyedProperty`, `VisitSetNamedProperty`, `VisitDefineNamedOwnProperty`, `VisitSetKeyedProperty`, `VisitDefineKeyedOwnProperty`, and `VisitStaInArrayLiteral` clearly relate to accessing and modifying object properties (both named and indexed). The presence of `feedback` suggests optimization based on runtime type information.

    * **Global Variable Access:** The `BuildLoadGlobal`, `VisitLdaModuleVariable`, and `VisitStaModuleVariable` sections handle accessing and modifying global variables and module variables.

    * **Constants:** The `GetConstant` and `GetTrustedConstant` functions are responsible for retrieving constant values.

    * **Binary and Unary Operations:** The `VisitAdd`, `VisitSub`, etc., and `VisitInc`, `VisitDec`, etc., sections handle basic arithmetic and logical operations.

    * **Control Flow and Deoptimization:**  While not explicitly a block here, the presence of `ReduceResult`, `kDoneWithValue`, `kDoneWithoutValue`, `kDoneWithAbort`, `EmitUnconditionalDeopt` indicates mechanisms for handling different outcomes of optimization attempts and for deoptimizing when assumptions are violated.

    * **For-In Loop Optimization:** The `TryBuildGetKeyedPropertyWithEnumeratedKey` and the `current_for_in_state` variable suggest an optimization specific to `for...in` loops.

4. **Analyzing Individual Function/Method Responsibilities:**  For each identified block, I'll examine the individual functions and their roles. For example:

    * `TryBuildNamedAccess`:  Attempts to optimize named property access based on feedback.
    * `RecordKnownProperty`: Stores information about known property values for later reuse.
    * `BuildLoadStringLength`:  Handles loading the `length` property of a string.
    * `VisitGetNamedProperty`:  The entry point when the V8 interpreter encounters a `GetNamedProperty` bytecode. It tries optimized paths and falls back to generic loads.

5. **Relating to JavaScript:** I'll consider how the C++ code maps to JavaScript concepts. Property access, global variables, arithmetic operations, and `for...in` loops are fundamental JavaScript features. I'll think of simple JavaScript examples that would trigger these code paths. For instance, `obj.prop`, `globalVar`, `a + b`, `for (let key in obj)`.

6. **Identifying Potential Errors:** I'll look for patterns that suggest common programming errors. Type mismatches leading to deoptimization, accessing non-existent properties, and incorrect assumptions about object structure are likely candidates.

7. **Inferring Assumptions and Logic:**  I'll try to deduce the underlying assumptions and logic. For instance, the code seems to heavily rely on type feedback for optimization. The presence of "generic" operations suggests a fallback mechanism when optimizations aren't possible.

8. **Considering the "Part 9 of 18" Context:** This indicates that the code is a piece of a larger compilation pipeline. The graph being built here is likely used in later stages for further optimization or code generation.

9. **Structuring the Output:**  I'll organize the information into the requested categories: functionality, Torque relation, JavaScript examples, code logic (input/output), common errors, and summary.

10. **Refinement and Iteration:** After the initial pass, I'll review the code and my analysis to ensure accuracy and completeness. I'll look for connections between different parts of the code and refine my understanding of their interactions. For example, I might notice the interplay between `TryBuildNamedAccess` and `RecordKnownProperty`.

By following these steps, I can systematically analyze the C++ code and provide a comprehensive answer to the prompt. The key is to break down the complex code into smaller, manageable parts and then synthesize the information to understand the overall functionality.
好的，让我们来分析一下 `v8/src/maglev/maglev-graph-builder.cc` 这个文件的功能。

**功能归纳:**

`v8/src/maglev/maglev-graph-builder.cc` 是 V8 引擎中 Maglev 编译器的一个核心组件，负责将 JavaScript 的中间表示（通常是 Bytecode 或 Ignition IR）转换成 Maglev 图。这个图是 Maglev 编译器的内部表示，用于后续的优化和代码生成。

**具体功能点:**

1. **构建 Maglev 图的基础结构:**  该文件定义了 `MaglevGraphBuilder` 类，这个类负责创建和连接 Maglev 图中的节点。这些节点代表了 JavaScript 代码中的各种操作，例如加载属性、调用函数、算术运算等。

2. **处理属性访问:**  文件中包含了大量的逻辑来优化属性的读取和写入操作 (`GetNamedProperty`, `SetNamedProperty`, `GetKeyedProperty` 等)。它会利用类型反馈信息 (`feedback`) 来尝试生成更高效的代码，例如直接访问对象的属性而无需进行复杂的查找。

3. **处理全局变量和模块变量:**  代码包含处理全局变量 (`LdaGlobal`) 和模块变量 (`LdaModuleVariable`, `StaModuleVariable`) 的逻辑，确保在 Maglev 图中正确表示这些变量的访问。

4. **处理常量:**  `GetConstant` 函数负责在 Maglev 图中创建和管理常量节点。

5. **处理二元和一元操作:**  文件中实现了各种二元运算符（加、减、乘、除等）和一元运算符（逻辑非、取反等）的图构建逻辑。

6. **处理类型转换和检查:**  虽然在这个代码片段中没有直接看到明显的类型转换操作，但可以推断 `MaglevGraphBuilder` 在构建图的过程中会涉及到类型检查和潜在的类型转换。

7. **利用类型反馈进行优化:** 代码中多次出现 `feedback` 相关的操作，这表明 `MaglevGraphBuilder` 依赖于 V8 运行时收集的类型反馈信息，以便进行有针对性的优化。 例如，根据属性访问的反馈，它可以选择内联属性访问或者进行更精确的类型检查。

8. **处理 `for...in` 循环:**  `TryBuildGetKeyedPropertyWithEnumeratedKey` 这部分代码表明 Maglev 编译器尝试优化 `for...in` 循环中的属性访问。

9. **处理 Super 属性访问:** `VisitGetNamedPropertyFromSuper` 专门处理通过 `super` 关键字访问父类属性的情况。

10. **处理数组字面量:** `VisitStaInArrayLiteral` 涉及到数组字面量的元素赋值操作。

**关于 .tq 结尾:**

如果 `v8/src/maglev/maglev-graph-builder.cc` 以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。 Torque 是 V8 使用的一种领域特定语言，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时库。  然而，根据你提供的文件路径和文件名，它以 `.cc` 结尾，所以它是标准的 C++ 源代码。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`v8/src/maglev/maglev-graph-builder.cc` 的核心作用是将 JavaScript 代码转换成更底层的表示形式，以便进行优化和执行。  以下是一些 JavaScript 示例以及它们在 `maglev-graph-builder.cc` 中可能涉及到的处理：

* **属性访问:**

```javascript
const obj = { a: 10 };
const x = obj.a; // 对应 VisitGetNamedProperty
obj.b = 20;     // 对应 VisitSetNamedProperty

const arr = [1, 2, 3];
const y = arr[0]; // 对应 VisitGetKeyedProperty
arr[1] = 4;     // 对应 VisitSetKeyedProperty
```

* **全局变量访问:**

```javascript
let globalVar = 5;
console.log(globalVar); // 对应 LdaGlobal
globalVar = 10;        // 对应 StaGlobal (虽然代码片段中未直接显示 StaGlobal，但其逻辑会类似)
```

* **模块变量访问:**

```javascript
// 假设在一个模块中
export let moduleVar = 15;
import { moduleVar } from './module';
console.log(moduleVar); // 对应 LdaModuleVariable
```

* **算术运算:**

```javascript
let a = 5;
let b = 10;
let sum = a + b;  // 对应 VisitAdd
let product = a * b; // 对应 VisitMul
```

* **`for...in` 循环:**

```javascript
const obj = { a: 1, b: 2 };
for (let key in obj) {
  console.log(key, obj[key]); // obj[key] 可能触发 TryBuildGetKeyedPropertyWithEnumeratedKey
}
```

* **`super` 关键字:**

```javascript
class Parent {
  parentMethod() { return 5; }
}

class Child extends Parent {
  childMethod() {
    return super.parentMethod() + 1; // 对应 VisitGetNamedPropertyFromSuper
  }
}
```

**代码逻辑推理 (假设输入与输出):**

假设有以下 JavaScript 代码片段：

```javascript
function foo(obj) {
  return obj.x + 1;
}
```

当 Maglev 编译器处理 `obj.x` 时，`VisitGetNamedProperty` 可能会被调用。

**假设输入:**

* `receiver`:  代表 `obj` 的 `ValueNode*`
* `name`:  代表属性名 "x" 的 `compiler::NameRef`
* `feedback_source`:  包含关于 `obj.x` 访问的反馈信息的对象。

**可能的输出 (取决于反馈信息):**

* **如果反馈表明 `obj` 总是具有名为 "x" 的属性，并且其值为数字:**  `TryBuildNamedAccess` 可能会成功构建一个优化的属性加载节点，直接访问 `obj` 的 "x" 属性，并返回代表该属性值的 `ValueNode*`。
* **如果反馈信息不足或表明类型不确定:**  代码可能会走到 `generic_access` 分支，构建一个更通用的 `LoadNamedGeneric` 节点，该节点在运行时会进行更多的检查。

接下来，对于 `+ 1` 操作，`VisitAdd` 可能会被调用，它会接收到 `obj.x` 的结果 `ValueNode*` 和常量 `1` 的 `ValueNode*`，并生成一个代表加法运算的 `ValueNode*`。

**用户常见的编程错误:**

* **访问未定义的属性:**  例如，如果 `obj` 没有 "x" 属性，`obj.x` 将返回 `undefined`。Maglev 编译器可能会尝试基于之前的反馈进行优化，如果假设 "x" 总是存在且是特定类型，则会导致 deoptimization。

```javascript
function bar(obj) {
  return obj.y.toUpperCase(); // 如果 obj 没有 y 属性，或者 y 不是字符串
}
```
Maglev 可能会根据反馈假设 `obj.y` 是字符串，然后尝试构建优化的 `toUpperCase` 调用。如果运行时 `obj.y` 是 `undefined`，则会抛出错误并可能导致 deoptimization。

* **类型不一致的属性赋值:**

```javascript
const myObj = { count: 0 };
function increment(obj) {
  obj.count++;
}
increment(myObj);
myObj.count = "not a number"; // 改变了属性的类型
increment(myObj); // 可能会导致基于之前数字类型的假设的优化失效
```
Maglev 可能会优化 `obj.count++` 假设 `count` 总是数字，但后续赋值为字符串会使这个假设失效。

**归纳其功能 (作为第 9 部分):**

作为 18 个部分中的第 9 部分，`v8/src/maglev/maglev-graph-builder.cc` 承担着将 JavaScript 代码初步转换为 Maglev 图的关键职责。在这个阶段，编译器会：

* **识别并表示 JavaScript 的基本操作:** 例如属性访问、算术运算、函数调用等。
* **利用类型反馈信息进行初步优化:**  虽然更深入的优化可能在后续阶段进行，但此阶段已经开始根据反馈信息生成更高效的节点。
* **为后续的优化和代码生成奠定基础:**  生成的 Maglev 图是后续优化 Pass 的输入。

考虑到这是中间部分，可以推断前面部分可能负责解析 JavaScript 代码并生成中间表示（例如 Bytecode 或 Ignition IR），而后续部分则会负责对 Maglev 图进行更深入的分析、优化和最终的代码生成。 `maglev-graph-builder.cc` 是连接前端解析和后端代码生成的重要桥梁。

### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共18部分，请归纳一下它的功能
```

### 源代码
```cpp
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
                                          GetChe
```