Response:
Let's break down the thought process for analyzing the C++ header file.

1. **Initial Understanding of the File Path and Name:** The file is located in `v8/src/compiler/` and named `js-native-context-specialization.h`. The `.h` extension signifies a header file in C++. The name suggests its core purpose: specializing the compilation process based on the "native context" of JavaScript.

2. **Scanning the Header Guard:**  The `#ifndef V8_COMPILER_JS_NATIVE_CONTEXT_SPECIALIZATION_H_` and `#define V8_COMPILER_JS_NATIVE_CONTEXT_SPECIALIZATION_H_` along with the matching `#endif` are standard C++ header guards. Their function is to prevent multiple inclusions of the header file in a single compilation unit. This is a basic but important piece of C++ structure.

3. **Include Directives:**  The `#include` directives reveal the dependencies of this class. Let's examine some key ones:
    * `<optional>`:  Indicates the use of `std::optional`, likely for cases where a value might or might not be present.
    * `"src/base/flags.h"`: Suggests the class uses a flag system for controlling its behavior. The `Flags` and `enum Flag` definitions confirm this.
    * `"src/compiler/graph-assembler.h"`, `"src/compiler/graph-reducer.h"`, `"src/compiler/js-heap-broker.h"`:  These are crucial compiler-related includes. "graph" strongly hints at V8's internal representation of code. "reducer" points to an optimization or transformation pass in the compilation pipeline. "js-heap-broker" suggests interaction with V8's memory management for JavaScript objects.
    * `"src/deoptimizer/deoptimize-reason.h"`:  Indicates that this class might be involved in scenarios where the optimized code needs to be abandoned (deoptimized).
    * `"src/zone/zone-containers.h"`:  Points to V8's zone allocation system, a way to manage memory efficiently within specific compilation phases.

4. **Namespace Declarations:** The code is within the `v8::internal::compiler` namespace, providing context about its location within the V8 codebase.

5. **Forward Declarations:** The forward declarations like `class Factory;`, `class JSGlobalObject;`, etc., are a common C++ practice to avoid circular dependencies and reduce compilation time. They declare the existence of these classes without needing their full definitions yet.

6. **The Core Class: `JSNativeContextSpecialization`:**  This is the central element. Let's examine its structure:
    * **Inheritance:** It inherits from `AdvancedReducer`. This solidifies the idea that this class is part of V8's compiler pipeline, acting as a transformation or optimization step.
    * **`enum Flag` and `using Flags`:** As suspected, this defines the flags that control the specialization process (e.g., `kBailoutOnUninitialized`).
    * **Constructors:** The constructors take `Editor*`, `JSGraph*`, `JSHeapBroker*`, etc. These arguments are essential for the specialization process, providing access to the graph being optimized, the heap information, and other compilation context. The deleted copy constructor and assignment operator are good C++ practice to prevent unintended copying of this complex object.
    * **`reducer_name()`:**  A standard method for reducers to identify themselves.
    * **`Reduce(Node* node)`:** The core method of a `Reducer`. It takes a node in the compiler's graph and attempts to apply a specialization or optimization to it.
    * **`GetMaxStringLength()`:**  A utility function, likely used for string-related optimizations. Its public status suggests it might be used in testing or other parts of the compiler.
    * **`Reduce...` Methods:** A large number of `Reduce` methods (e.g., `ReduceJSAdd`, `ReduceJSLoadGlobal`, `ReduceJSSetNamedProperty`). This is the heart of the specialization logic. Each method likely handles a specific type of JavaScript operation (represented as a node in the graph). The names clearly indicate the JavaScript constructs being targeted.
    * **`ValueEffectControl`:** A nested class to represent the result of operations in the compiler graph, encapsulating the value produced, any side effects, and control flow changes.
    * **`BuildPropertyAccess`, `BuildElementAccess`, etc.:** These methods suggest the class constructs new parts of the compiler graph to implement specialized versions of property and element access.
    * **`InlinePropertyGetterCall`, `InlinePropertySetterCall`, `InlineApiCall`:** These hint at inlining optimizations, replacing function calls with the function's body.
    * **Helper Methods:**  Functions like `CreateStringConstant`, `Concatenate`, `StringCanSafelyBeRead`, `CanTreatHoleAsUndefined`, `InferMaps`, etc., perform supporting tasks for the main specialization logic.
    * **Getter Methods:**  Methods like `graph()`, `jsgraph()`, `broker()`, etc., provide access to the internal state of the `JSNativeContextSpecialization` object.
    * **Member Variables:**  The private member variables store the necessary context for specialization: the graph, heap broker, flags, global objects, zones, and a type cache.

7. **Considering the `.tq` Question:** The question about the `.tq` extension immediately flags Torque. Recognizing that Torque is V8's type system and language for implementing built-in functions, the answer should clearly differentiate between C++ (`.h`) and Torque (`.tq`).

8. **JavaScript Relationship and Examples:**  Connecting the C++ code to JavaScript requires identifying the JavaScript operations being specialized. The `ReduceJS...` method names are the key here. For example, `ReduceJSLoadGlobal` directly relates to accessing global variables in JavaScript. Constructing simple JavaScript examples that demonstrate these operations is crucial.

9. **Code Logic Inference:**  Focus on the *intent* of the `Reduce` methods. For `ReduceJSLoadGlobal`, the goal is likely to determine the value of a global variable at compile time if possible, thus optimizing the load. The input would be a "LoadGlobal" node, and the output would be a node representing the constant value or a specialized load operation.

10. **Common Programming Errors:** Think about common mistakes related to the JavaScript features being optimized. For example, using a global variable before it's initialized is a classic error related to `ReduceJSLoadGlobal`. Type errors are relevant to property access specialization.

11. **Review and Refine:** After drafting the initial analysis, review it for clarity, accuracy, and completeness. Ensure the JavaScript examples are correct and the explanations are easy to understand. Make sure to explicitly address all parts of the prompt.

By following this structured approach, analyzing the header file becomes a systematic process, leading to a comprehensive understanding of its functionality and its relationship to JavaScript.
好的，我们来分析一下 `v8/src/compiler/js-native-context-specialization.h` 这个 V8 源代码文件。

**文件功能概述**

`JSNativeContextSpecialization` 类是 V8 编译器中的一个关键组件，它的主要功能是在编译过程中，**基于当前的 Native Context（可以理解为 JavaScript 代码运行的环境）对 JavaScript 代码的中间表示形式（JSGraph）进行特化和优化。**

更具体地说，它尝试做以下几件事情：

* **常量折叠 (Constant Folding):**  如果能在编译时确定某些全局变量的值，就直接将这些值替换到代码中，避免运行时的查找。这主要针对 `LoadGlobal` 节点。
* **强度降低 (Strength Reduction):** 对于某些 `StoreGlobal` 操作，如果可以确定存储的值，可以进行优化，例如避免不必要的副作用。
* **基于类型反馈的优化:** 利用 V8 运行时收集的类型反馈信息，对 `LoadNamed` (属性读取) 和 `SetNamedProperty` (属性设置) 等操作进行特化。例如，如果知道某个属性总是访问特定类型的对象，就可以生成更高效的代码。
* **内联 (Inlining):** 对于某些特定的属性访问器 (getter/setter)，尝试将其调用内联到调用点，减少函数调用的开销。
* **字符串常量连接优化:**  如果能在编译时确定字符串连接的结果，就直接生成连接后的字符串常量。
* **其他特定 JavaScript 语法的优化:**  针对 `instanceof`、原型链查找、Promise 解析等特定 JavaScript 语法进行优化。

**关于文件扩展名 `.tq`**

如果 `v8/src/compiler/js-native-context-specialization.h` 以 `.tq` 结尾，那么它将是 **V8 的 Torque 源代码**。Torque 是 V8 内部使用的一种类型化的领域特定语言，用于实现 V8 的内置函数和一些关键的运行时组件。

但根据你提供的文件内容，它以 `.h` 结尾，所以它是一个 **C++ 头文件**。

**与 JavaScript 功能的关系及示例**

`JSNativeContextSpecialization` 直接影响着 JavaScript 代码的执行效率。它通过在编译时进行优化，减少了运行时的工作量，从而提高了性能。

以下是一些与 `JSNativeContextSpecialization` 相关的 JavaScript 功能及其优化的例子：

1. **全局变量访问优化 (`ReduceJSLoadGlobal`)：**

   ```javascript
   const PI = 3.14159;
   function calculateArea(radius) {
     return PI * radius * radius;
   }
   ```

   **优化:** 如果 `PI` 在编译时可以被确定为常量，`JSNativeContextSpecialization` 可能会将 `PI` 的值直接嵌入到 `calculateArea` 函数的代码中，避免每次调用时都去查找全局变量 `PI`。

2. **属性访问优化 (`ReduceJSLoadNamed`)：**

   ```javascript
   const obj = { x: 10, y: 20 };
   function getX(o) {
     return o.x;
   }
   ```

   **优化:** 如果 V8 收集到类型反馈，了解到 `getX` 函数通常接收具有属性 `x` 的对象，并且 `x` 的类型总是数字，`JSNativeContextSpecialization` 可能会生成专门的代码来快速访问 `o.x`，例如直接访问对象内部的特定偏移量。

3. **属性设置优化 (`ReduceJSSetNamedProperty`)：**

   ```javascript
   const obj = {};
   function setX(o, value) {
     o.x = value;
   }
   ```

   **优化:**  类似于属性访问，如果类型反馈表明 `value` 总是某种特定类型，可以优化属性设置操作，例如避免不必要的类型检查。

4. **字符串常量连接优化 (`ReduceJSAdd`)：**

   ```javascript
   const greeting = "Hello, " + "world!";
   ```

   **优化:** `JSNativeContextSpecialization` 可以在编译时将 `"Hello, "` 和 `"world!"` 连接起来，生成常量字符串 `"Hello, world!"`，避免运行时的连接操作。

5. **`instanceof` 优化 (`ReduceJSInstanceOf`)：**

   ```javascript
   function checkInstance(obj) {
     return obj instanceof Array;
   }
   ```

   **优化:** 如果编译时能确定 `Array` 的构造函数没有被修改，并且 `obj` 的类型信息足够明确，可以优化 `instanceof` 的检查过程。

**代码逻辑推理示例**

假设我们关注 `ReduceJSLoadGlobal` 方法。

**假设输入:**

* `node`: 一个代表 `LoadGlobal` 操作的节点，它尝试加载名为 `"PI"` 的全局变量。
* 当前的 Native Context 中，全局变量 `PI` 已经被初始化为常量值 `3.14159`。

**代码逻辑推理:**

`ReduceJSLoadGlobal` 方法会检查以下内容：

1. **全局变量是否存在:** 检查当前 Native Context 中是否存在名为 `"PI"` 的全局变量。
2. **全局变量是否已初始化:**  确认该全局变量是否已经被赋值。
3. **全局变量的值是否为常量:**  判断该全局变量的值是否是常量，并且在编译时可以确定。

**输出:**

如果以上条件都满足，`ReduceJSLoadGlobal` 可能会将 `LoadGlobal` 节点替换为一个表示常量 `3.14159` 的节点。这意味着在最终生成的机器码中，将直接使用 `3.14159` 这个值，而不会执行实际的全局变量查找操作。

**涉及用户常见的编程错误及示例**

`JSNativeContextSpecialization` 的优化有时会受到用户编程错误的影响。以下是一些例子：

1. **在全局作用域中重复声明变量：**

   ```javascript
   var globalVar = 10;
   // ... 很多代码 ...
   var globalVar = 20; // 潜在的错误
   ```

   **影响:**  如果 `JSNativeContextSpecialization` 基于之前的类型反馈或假设优化了对 `globalVar` 的访问，后面的重复声明可能会导致优化失效，甚至产生意想不到的行为。V8 的优化器可能会做出一些基于先前假设的决策，而重复声明会改变这些假设。

2. **意外地修改内置对象的原型：**

   ```javascript
   Array.prototype.myCustomMethod = function() {
     console.log("Custom method");
   };

   const arr = [1, 2, 3];
   arr.myCustomMethod();
   ```

   **影响:** V8 的很多优化都依赖于内置对象（如 `Array`、`Object` 等）的原型结构保持不变。如果用户修改了内置对象的原型，`JSNativeContextSpecialization` 之前进行的基于原型结构的优化可能会失效，导致性能下降或行为异常。V8 也会采取一些措施来追踪原型修改，并可能因此放弃某些激进的优化。

3. **过早地访问未初始化的全局变量 (在模块环境中可能更常见):**

   ```javascript
   console.log(myGlobalVar); // 错误：myGlobalVar 在此处未定义

   var myGlobalVar = 10;
   ```

   **影响:** 虽然 JavaScript 允许在声明之前访问 `var` 声明的变量（值为 `undefined`），但在模块环境中，访问未初始化的变量会抛出错误。`JSNativeContextSpecialization` 在尝试优化全局变量访问时，需要考虑变量的初始化状态。

**总结**

`v8/src/compiler/js-native-context-specialization.h` 定义的 `JSNativeContextSpecialization` 类是 V8 编译器中一个至关重要的优化阶段。它利用 Native Context 的信息和类型反馈来特化 JavaScript 代码，提高执行效率。理解它的功能有助于我们更好地理解 V8 的编译原理以及如何编写更易于优化的 JavaScript 代码。

### 提示词
```
这是目录为v8/src/compiler/js-native-context-specialization.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-native-context-specialization.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_JS_NATIVE_CONTEXT_SPECIALIZATION_H_
#define V8_COMPILER_JS_NATIVE_CONTEXT_SPECIALIZATION_H_

#include <optional>

#include "src/base/flags.h"
#include "src/compiler/graph-assembler.h"
#include "src/compiler/graph-reducer.h"
#include "src/compiler/js-heap-broker.h"
#include "src/deoptimizer/deoptimize-reason.h"
#include "src/zone/zone-containers.h"

namespace v8 {
namespace internal {

// Forward declarations.
class Factory;
class JSGlobalObject;
class JSGlobalProxy;

namespace compiler {

// Forward declarations.
enum class AccessMode;
class CommonOperatorBuilder;
class CompilationDependencies;
class ElementAccessInfo;
class JSGraph;
class JSHeapBroker;
class JSOperatorBuilder;
class MachineOperatorBuilder;
class PropertyAccessInfo;
class SimplifiedOperatorBuilder;
class TypeCache;

// Specializes a given JSGraph to a given native context, potentially constant
// folding some {LoadGlobal} nodes or strength reducing some {StoreGlobal}
// nodes.  And also specializes {LoadNamed} and {SetNamedProperty} nodes
// according to type feedback (if available).
class V8_EXPORT_PRIVATE JSNativeContextSpecialization final
    : public AdvancedReducer {
 public:
  // Flags that control the mode of operation.
  enum Flag {
    kNoFlags = 0u,
    kBailoutOnUninitialized = 1u << 0,
  };
  using Flags = base::Flags<Flag>;

  JSNativeContextSpecialization(Editor* editor, JSGraph* jsgraph,
                                JSHeapBroker* broker, Flags flags, Zone* zone,
                                Zone* shared_zone);
  JSNativeContextSpecialization(const JSNativeContextSpecialization&) = delete;
  JSNativeContextSpecialization& operator=(
      const JSNativeContextSpecialization&) = delete;

  const char* reducer_name() const override {
    return "JSNativeContextSpecialization";
  }

  Reduction Reduce(Node* node) final;

  // Utility for folding string constant concatenation.
  // Supports JSAdd nodes and nodes typed as string or number.
  // Public for the sake of unit testing.
  static std::optional<size_t> GetMaxStringLength(JSHeapBroker* broker,
                                                  Node* node);

 private:
  Reduction ReduceJSAdd(Node* node);
  Reduction ReduceJSAsyncFunctionEnter(Node* node);
  Reduction ReduceJSAsyncFunctionReject(Node* node);
  Reduction ReduceJSAsyncFunctionResolve(Node* node);
  Reduction ReduceJSGetSuperConstructor(Node* node);
  Reduction ReduceJSFindNonDefaultConstructorOrConstruct(Node* node);
  Reduction ReduceJSInstanceOf(Node* node);
  Reduction ReduceJSHasInPrototypeChain(Node* node);
  Reduction ReduceJSOrdinaryHasInstance(Node* node);
  Reduction ReduceJSPromiseResolve(Node* node);
  Reduction ReduceJSResolvePromise(Node* node);
  Reduction ReduceJSLoadGlobal(Node* node);
  Reduction ReduceJSStoreGlobal(Node* node);
  Reduction ReduceJSLoadNamed(Node* node);
  Reduction ReduceJSLoadNamedFromSuper(Node* node);
  Reduction ReduceJSGetIterator(Node* node);
  Reduction ReduceJSSetNamedProperty(Node* node);
  Reduction ReduceJSHasProperty(Node* node);
  Reduction ReduceJSLoadProperty(Node* node);
  Reduction ReduceJSSetKeyedProperty(Node* node);
  Reduction ReduceJSDefineKeyedOwnProperty(Node* node);
  Reduction ReduceJSDefineNamedOwnProperty(Node* node);
  Reduction ReduceJSDefineKeyedOwnPropertyInLiteral(Node* node);
  Reduction ReduceJSStoreInArrayLiteral(Node* node);
  Reduction ReduceJSToObject(Node* node);

  Reduction ReduceElementAccess(Node* node, Node* index, Node* value,
                                ElementAccessFeedback const& feedback);
  // In the case of non-keyed (named) accesses, pass the name as {static_name}
  // and use {nullptr} for {key} (load/store modes are irrelevant).
  Reduction ReducePropertyAccess(Node* node, Node* key,
                                 OptionalNameRef static_name, Node* value,
                                 FeedbackSource const& source,
                                 AccessMode access_mode);
  Reduction ReduceNamedAccess(Node* node, Node* value,
                              NamedAccessFeedback const& feedback,
                              AccessMode access_mode, Node* key = nullptr);
  Reduction ReduceMegaDOMPropertyAccess(
      Node* node, Node* value, MegaDOMPropertyAccessFeedback const& feedback,
      FeedbackSource const& source);
  Reduction ReduceGlobalAccess(Node* node, Node* lookup_start_object,
                               Node* receiver, Node* value, NameRef name,
                               AccessMode access_mode, Node* key,
                               PropertyCellRef property_cell,
                               Node* effect = nullptr);
  Reduction ReduceElementLoadFromHeapConstant(Node* node, Node* key,
                                              AccessMode access_mode,
                                              KeyedAccessLoadMode load_mode);
  Reduction ReduceElementAccessOnString(Node* node, Node* index, Node* value,
                                        KeyedAccessMode const& keyed_mode);

  Reduction ReduceEagerDeoptimize(Node* node, DeoptimizeReason reason);
  Reduction ReduceJSToString(Node* node);

  Reduction ReduceJSLoadPropertyWithEnumeratedKey(Node* node);

  Handle<String> CreateStringConstant(Node* node);

  // A triple of nodes that represents a continuation.
  class ValueEffectControl final {
   public:
    ValueEffectControl()
        : value_(nullptr), effect_(nullptr), control_(nullptr) {}
    ValueEffectControl(Node* value, Node* effect, Node* control)
        : value_(value), effect_(effect), control_(control) {}

    Node* value() const { return value_; }
    Node* effect() const { return effect_; }
    Node* control() const { return control_; }

   private:
    Node* value_;
    Node* effect_;
    Node* control_;
  };

  // Construct the appropriate subgraph for property access. Return {} if the
  // property access couldn't be built.
  std::optional<ValueEffectControl> BuildPropertyAccess(
      Node* lookup_start_object, Node* receiver, Node* value, Node* context,
      Node* frame_state, Node* effect, Node* control, NameRef name,
      ZoneVector<Node*>* if_exceptions, PropertyAccessInfo const& access_info,
      AccessMode access_mode);
  std::optional<ValueEffectControl> BuildPropertyLoad(
      Node* lookup_start_object, Node* receiver, Node* context,
      Node* frame_state, Node* effect, Node* control, NameRef name,
      ZoneVector<Node*>* if_exceptions, PropertyAccessInfo const& access_info);

  ValueEffectControl BuildPropertyStore(Node* receiver, Node* value,
                                        Node* context, Node* frame_state,
                                        Node* effect, Node* control,
                                        NameRef name,
                                        ZoneVector<Node*>* if_exceptions,
                                        PropertyAccessInfo const& access_info,
                                        AccessMode access_mode);

  ValueEffectControl BuildPropertyTest(Node* effect, Node* control,
                                       PropertyAccessInfo const& access_info);

  // Helpers for accessor inlining.
  Node* InlinePropertyGetterCall(Node* receiver,
                                 ConvertReceiverMode receiver_mode,
                                 Node* lookup_start_object, Node* context,
                                 Node* frame_state, Node** effect,
                                 Node** control,
                                 ZoneVector<Node*>* if_exceptions,
                                 PropertyAccessInfo const& access_info);
  void InlinePropertySetterCall(Node* receiver, Node* value, Node* context,
                                Node* frame_state, Node** effect,
                                Node** control,
                                ZoneVector<Node*>* if_exceptions,
                                PropertyAccessInfo const& access_info);
  Node* InlineApiCall(Node* receiver, Node* api_holder, Node* frame_state,
                      Node* value, Node** effect, Node** control,
                      FunctionTemplateInfoRef function_template_info);

  // Construct the appropriate subgraph for element access.
  ValueEffectControl BuildElementAccess(Node* receiver, Node* index,
                                        Node* value, Node* effect,
                                        Node* control, Node* context,
                                        ElementAccessInfo const& access_info,
                                        KeyedAccessMode const& keyed_mode);
  ValueEffectControl BuildElementAccessForTypedArrayOrRabGsabTypedArray(
      Node* receiver, Node* index, Node* value, Node* effect, Node* control,
      Node* context, ElementsKind elements_kind,
      KeyedAccessMode const& keyed_mode);

  // Construct appropriate subgraph to load from a String.
  Node* BuildIndexedStringLoad(Node* receiver, Node* index, Node* length,
                               Node** effect, Node** control,
                               KeyedAccessLoadMode load_mode);

  // Construct appropriate subgraph to extend properties backing store.
  Node* BuildExtendPropertiesBackingStore(MapRef map, Node* properties,
                                          Node* effect, Node* control);

  // Construct appropriate subgraph to check that the {value} matches
  // the previously recorded {name} feedback.
  Node* BuildCheckEqualsName(NameRef name, Node* value, Node* effect,
                             Node* control);

  // Concatenates {left} and {right}.
  Handle<String> Concatenate(Handle<String> left, Handle<String> right);

  // Returns true if {str} can safely be read:
  //   - if we are on the main thread, then any string can safely be read
  //   - in the background, we can only read some string shapes, except if we
  //     created the string ourselves.
  // {node} is the node from which we got {str}, but which is still taken as
  // parameter to simplify the checks.
  bool StringCanSafelyBeRead(Node* const node, Handle<String> str);

  // Checks if we can turn the hole into undefined when loading an element
  // from an object with one of the {receiver_maps}; sets up appropriate
  // code dependencies and might use the array protector cell.
  bool CanTreatHoleAsUndefined(ZoneVector<MapRef> const& receiver_maps);

  void RemoveImpossibleMaps(Node* object, ZoneVector<MapRef>* maps) const;

  ElementAccessFeedback const& TryRefineElementAccessFeedback(
      ElementAccessFeedback const& feedback, Node* receiver,
      Effect effect) const;

  // Try to infer maps for the given {object} at the current {effect}.
  bool InferMaps(Node* object, Effect effect, ZoneVector<MapRef>* maps) const;

  // Try to infer a root map for the {object} independent of the current program
  // location.
  OptionalMapRef InferRootMap(Node* object) const;

  // Checks if we know at compile time that the {receiver} either definitely
  // has the {prototype} in it's prototype chain, or the {receiver} definitely
  // doesn't have the {prototype} in it's prototype chain.
  enum InferHasInPrototypeChainResult {
    kIsInPrototypeChain,
    kIsNotInPrototypeChain,
    kMayBeInPrototypeChain
  };
  InferHasInPrototypeChainResult InferHasInPrototypeChain(
      Node* receiver, Effect effect, HeapObjectRef prototype);

  Node* BuildLoadPrototypeFromObject(Node* object, Node* effect, Node* control);

  std::pair<Node*, Node*> ReleaseEffectAndControlFromAssembler(
      JSGraphAssembler* assembler);

  Graph* graph() const;
  JSGraph* jsgraph() const { return jsgraph_; }

  JSHeapBroker* broker() const { return broker_; }
  Isolate* isolate() const;
  Factory* factory() const;
  CommonOperatorBuilder* common() const;
  JSOperatorBuilder* javascript() const;
  SimplifiedOperatorBuilder* simplified() const;
  Flags flags() const { return flags_; }
  Handle<JSGlobalObject> global_object() const { return global_object_; }
  Handle<JSGlobalProxy> global_proxy() const { return global_proxy_; }
  NativeContextRef native_context() const {
    return broker()->target_native_context();
  }
  CompilationDependencies* dependencies() const {
    return broker()->dependencies();
  }
  Zone* zone() const { return zone_; }
  Zone* shared_zone() const { return shared_zone_; }

  JSGraph* const jsgraph_;
  JSHeapBroker* const broker_;
  Flags const flags_;
  Handle<JSGlobalObject> global_object_;
  Handle<JSGlobalProxy> global_proxy_;
  Zone* const zone_;
  Zone* const shared_zone_;
  TypeCache const* type_cache_;
  ZoneUnorderedSet<IndirectHandle<String>, IndirectHandle<String>::hash,
                   IndirectHandle<String>::equal_to>
      created_strings_;
};

DEFINE_OPERATORS_FOR_FLAGS(JSNativeContextSpecialization::Flags)

}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_COMPILER_JS_NATIVE_CONTEXT_SPECIALIZATION_H_
```