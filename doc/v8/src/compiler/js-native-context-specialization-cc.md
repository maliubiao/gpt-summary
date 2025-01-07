Response:
The user wants me to analyze the provided C++ code snippet from V8's `js-native-context-specialization.cc`. I need to identify its functionalities.

Here's a plan:
1. **High-level overview:** Understand the purpose of the file based on its name and the included headers.
2. **Function breakdown:** Analyze the `Reduce` method and the individual `ReduceJS...` methods. Identify the specific JavaScript operations they are trying to optimize or specialize.
3. **Torque analysis:** Confirm that the file is not a Torque file.
4. **JavaScript relationship:** For methods related to JavaScript functionality, provide illustrative JavaScript examples.
5. **Logic inference:** For methods with code logic, deduce the input and output based on the code.
6. **Common errors:** Identify potential user programming errors that these specializations might address or be related to.
7. **Summarize:** Provide a concise summary of the file's overall purpose based on the above analysis.
这是 V8 源代码文件 `v8/src/compiler/js-native-context-specialization.cc` 的第一部分，其主要功能是**在编译过程中对特定的 JavaScript 操作进行基于原生上下文的优化和特化**。

以下是更详细的分析：

1. **文件类型：**
   - 该文件以 `.cc` 结尾，表明它是一个 C++ 源代码文件，而不是以 `.tq` 结尾的 Torque 源代码文件。

2. **核心功能：**
   - 该文件定义了一个名为 `JSNativeContextSpecialization` 的类，这个类继承自 `AdvancedReducer`，意味着它在 V8 的编译管道中作为一个优化阶段存在。
   - `JSNativeContextSpecialization` 的主要任务是通过 `Reduce` 方法来检查和转换抽象语法树（AST）中的节点（`Node* node`）。
   - `Reduce` 方法内部通过 `switch` 语句处理不同的 `IrOpcode`，这些 `IrOpcode` 代表不同的 JavaScript 操作（例如 `kJSAdd`、`kJSAsyncFunctionEnter`、`kJSLoadGlobal` 等）。
   - 针对每个特定的 JavaScript 操作，`JSNativeContextSpecialization` 尝试进行优化，例如：
     - **常量折叠：** 如果操作数是常量（例如字符串或数字），则在编译时计算结果。例如，对于 `kJSAdd`，如果两个操作数都是字符串常量，则会预先拼接字符串。
     - **基于类型的优化：**  根据操作数的已知类型进行优化。例如，对于 `kJSToString`，如果输入已经是字符串，则直接返回输入。
     - **内联或替换：** 将某些复杂的 JavaScript 操作替换为更简单的操作或内联其实现。例如，对于某些 `kJSInstanceOf` 调用，可以进行特化处理。
     - **依赖管理：**  通过 `dependencies()` 记录编译时做的假设，以便在运行时这些假设失效时进行反优化（deoptimization）。

3. **与 JavaScript 功能的关系及示例：**

   以下列举一些 `ReduceJS...` 方法以及它们对应的 JavaScript 功能和例子：

   - **`ReduceJSAdd(Node* node)`:** 对应 JavaScript 的加法运算符 `+`。
     ```javascript
     const str1 = "hello";
     const str2 = "world";
     const result = str1 + str2; // JSNativeContextSpecialization 可能会在编译时将 "hello" + "world" 折叠为 "helloworld"
     ```

   - **`ReduceJSToString(Node* node)`:** 对应 JavaScript 的类型转换到字符串，例如 `String(value)` 或隐式类型转换。
     ```javascript
     const num = 123;
     const str = String(num); // JSNativeContextSpecialization 可能会在编译时将数字常量转换为字符串常量
     const obj = { toString: () => "custom" };
     const strFromObj = String(obj);
     ```

   - **`ReduceJSAsyncFunctionEnter(Node* node)`:** 对应 `async function` 的入口。
     ```javascript
     async function myFunction() {
       console.log("Inside async function");
       return 10;
     }
     ```

   - **`ReduceJSLoadGlobal(Node* node)`:** 对应访问全局变量。
     ```javascript
     console.log(window.innerWidth); // 访问全局变量 window
     ```

   - **`ReduceJSStoreGlobal(Node* node)`:** 对应给全局变量赋值。
     ```javascript
     window.myGlobalVar = 100;
     ```

   - **`ReduceJSLoadNamed(Node* node)`:** 对应访问对象的属性（例如 `object.property`）。
     ```javascript
     const obj = { name: "example" };
     console.log(obj.name);
     ```

   - **`ReduceJSSetNamedProperty(Node* node)`:** 对应设置对象的属性（例如 `object.property = value`）。
     ```javascript
     const obj = {};
     obj.age = 30;
     ```

   - **`ReduceJSInstanceOf(Node* node)`:** 对应 `instanceof` 运算符。
     ```javascript
     const arr = [];
     console.log(arr instanceof Array); // true
     ```

4. **代码逻辑推理及假设输入输出：**

   以 `ReduceJSAdd(Node* node)` 为例，假设输入 `node` 代表 `a + b` 这个 JavaScript 操作：

   **假设输入：**
   - `lhs` (左操作数节点) 是一个 `HeapConstant<String>`，值为 "hello"。
   - `rhs` (右操作数节点) 是一个 `HeapConstant<String>`，值为 " world"。

   **代码逻辑：**
   - `GetMaxStringLength` 会返回 "hello" 的长度 5 和 " world" 的长度 6。
   - 检查总长度 5 + 6 = 11 是否小于 `String::kMaxLength`。
   - 检查 `lhs` 和 `rhs` 都是字符串常量。
   - `Concatenate` 函数会将 "hello" 和 " world" 拼接成 "hello world"。
   - 创建一个新的 `HeapConstant` 节点，其值为字符串 "hello world"。

   **假设输出：**
   - `ReduceJSAdd` 方法返回 `Changed` 的 Reduction，并将原始的 `JSAdd` 节点替换为一个新的 `HeapConstant` 节点，值为 "hello world"。

5. **涉及用户常见的编程错误：**

   - **类型错误导致的隐式类型转换：**  例如，使用 `+` 运算符连接一个字符串和一个非字符串类型的值，可能会导致意外的字符串拼接。 `JSNativeContextSpecialization` 在处理 `kJSAdd` 时，会对字符串常量进行特化，这在一定程度上可以优化这种模式。

     ```javascript
     const name = "Alice";
     const age = 30;
     const message = "Name: " + name + ", Age: " + age; // 容易理解，但可能涉及多次字符串拼接
     ```

   - **低效的字符串拼接：**  在循环中频繁使用 `+` 运算符拼接字符串可能会导致性能问题。虽然 `JSNativeContextSpecialization` 对常量字符串拼接进行了优化，但对动态拼接的优化可能有限。

     ```javascript
     let longString = "";
     for (let i = 0; i < 1000; i++) {
       longString += "a"; // 循环中频繁拼接字符串，效率较低
     }
     ```

6. **功能归纳 (第 1 部分)：**

   `v8/src/compiler/js-native-context-specialization.cc` 的第一部分主要负责在编译时对一些基础的 JavaScript 操作（如加法、类型转换到字符串、异步函数入口等）进行基于上下文的优化。它通过检查操作数的类型和值，特别是针对常量的情况，来执行常量折叠、类型特化等优化，以提升代码执行效率。它还处理了异步函数的初始化，并为后续的异步操作做准备。总而言之，这一部分是 V8 编译器中一个重要的优化阶段，旨在提高特定 JavaScript 代码模式的性能。

Prompt: 
```
这是目录为v8/src/compiler/js-native-context-specialization.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-native-context-specialization.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/js-native-context-specialization.h"

#include <optional>

#include "src/base/logging.h"
#include "src/builtins/accessors.h"
#include "src/codegen/code-factory.h"
#include "src/common/globals.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/access-info.h"
#include "src/compiler/allocation-builder-inl.h"
#include "src/compiler/allocation-builder.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/compiler/frame-states.h"
#include "src/compiler/graph-assembler.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/js-operator.h"
#include "src/compiler/linkage.h"
#include "src/compiler/map-inference.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/property-access-builder.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/type-cache.h"
#include "src/flags/flags.h"
#include "src/handles/handles.h"
#include "src/heap/factory.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/objects/elements-kind.h"
#include "src/objects/feedback-vector.h"
#include "src/objects/heap-number.h"
#include "src/objects/string.h"

namespace v8 {
namespace internal {
namespace compiler {

namespace {

bool HasNumberMaps(JSHeapBroker* broker, ZoneVector<MapRef> const& maps) {
  for (MapRef map : maps) {
    if (map.IsHeapNumberMap()) return true;
  }
  return false;
}

bool HasOnlyJSArrayMaps(JSHeapBroker* broker, ZoneVector<MapRef> const& maps) {
  for (MapRef map : maps) {
    if (!map.IsJSArrayMap()) return false;
  }
  return true;
}

}  // namespace

JSNativeContextSpecialization::JSNativeContextSpecialization(
    Editor* editor, JSGraph* jsgraph, JSHeapBroker* broker, Flags flags,
    Zone* zone, Zone* shared_zone)
    : AdvancedReducer(editor),
      jsgraph_(jsgraph),
      broker_(broker),
      flags_(flags),
      global_object_(
          broker->target_native_context().global_object(broker).object()),
      global_proxy_(
          broker->target_native_context().global_proxy_object(broker).object()),
      zone_(zone),
      shared_zone_(shared_zone),
      type_cache_(TypeCache::Get()),
      created_strings_(zone) {}

Reduction JSNativeContextSpecialization::Reduce(Node* node) {
  switch (node->opcode()) {
    case IrOpcode::kJSAdd:
      return ReduceJSAdd(node);
    case IrOpcode::kJSAsyncFunctionEnter:
      return ReduceJSAsyncFunctionEnter(node);
    case IrOpcode::kJSAsyncFunctionReject:
      return ReduceJSAsyncFunctionReject(node);
    case IrOpcode::kJSAsyncFunctionResolve:
      return ReduceJSAsyncFunctionResolve(node);
    case IrOpcode::kJSGetSuperConstructor:
      return ReduceJSGetSuperConstructor(node);
    case IrOpcode::kJSFindNonDefaultConstructorOrConstruct:
      return ReduceJSFindNonDefaultConstructorOrConstruct(node);
    case IrOpcode::kJSInstanceOf:
      return ReduceJSInstanceOf(node);
    case IrOpcode::kJSHasInPrototypeChain:
      return ReduceJSHasInPrototypeChain(node);
    case IrOpcode::kJSOrdinaryHasInstance:
      return ReduceJSOrdinaryHasInstance(node);
    case IrOpcode::kJSPromiseResolve:
      return ReduceJSPromiseResolve(node);
    case IrOpcode::kJSResolvePromise:
      return ReduceJSResolvePromise(node);
    case IrOpcode::kJSLoadGlobal:
      return ReduceJSLoadGlobal(node);
    case IrOpcode::kJSStoreGlobal:
      return ReduceJSStoreGlobal(node);
    case IrOpcode::kJSLoadNamed:
      return ReduceJSLoadNamed(node);
    case IrOpcode::kJSLoadNamedFromSuper:
      return ReduceJSLoadNamedFromSuper(node);
    case IrOpcode::kJSSetNamedProperty:
      return ReduceJSSetNamedProperty(node);
    case IrOpcode::kJSHasProperty:
      return ReduceJSHasProperty(node);
    case IrOpcode::kJSLoadProperty:
      return ReduceJSLoadProperty(node);
    case IrOpcode::kJSSetKeyedProperty:
      return ReduceJSSetKeyedProperty(node);
    case IrOpcode::kJSDefineKeyedOwnProperty:
      return ReduceJSDefineKeyedOwnProperty(node);
    case IrOpcode::kJSDefineNamedOwnProperty:
      return ReduceJSDefineNamedOwnProperty(node);
    case IrOpcode::kJSDefineKeyedOwnPropertyInLiteral:
      return ReduceJSDefineKeyedOwnPropertyInLiteral(node);
    case IrOpcode::kJSStoreInArrayLiteral:
      return ReduceJSStoreInArrayLiteral(node);
    case IrOpcode::kJSToObject:
      return ReduceJSToObject(node);
    case IrOpcode::kJSToString:
      return ReduceJSToString(node);
    case IrOpcode::kJSGetIterator:
      return ReduceJSGetIterator(node);
    default:
      break;
  }
  return NoChange();
}

// If {node} is a HeapConstant<String>, return the String's length. If {node} is
// a number, return the maximum size that a stringified number can have.
// Otherwise, we can't easily convert {node} into a String, and we return
// nullopt.
// static
std::optional<size_t> JSNativeContextSpecialization::GetMaxStringLength(
    JSHeapBroker* broker, Node* node) {
  HeapObjectMatcher matcher(node);
  if (matcher.HasResolvedValue() && matcher.Ref(broker).IsString()) {
    StringRef input = matcher.Ref(broker).AsString();
    return input.length();
  }

  NumberMatcher number_matcher(node);
  if (number_matcher.HasResolvedValue()) {
    return kMaxDoubleStringLength;
  }

  // We don't support objects with possibly monkey-patched prototype.toString
  // as it might have side-effects, so we shouldn't attempt lowering them.
  return std::nullopt;
}

Reduction JSNativeContextSpecialization::ReduceJSToString(Node* node) {
  DCHECK_EQ(IrOpcode::kJSToString, node->opcode());
  Node* const input = node->InputAt(0);

  HeapObjectMatcher matcher(input);
  if (matcher.HasResolvedValue() && matcher.Ref(broker()).IsString()) {
    Reduction reduction = Changed(input);  // JSToString(x:string) => x
    ReplaceWithValue(node, reduction.replacement());
    return reduction;
  }

  // TODO(turbofan): This optimization is weaker than what we used to have
  // in js-typed-lowering for OrderedNumbers. We don't have types here though,
  // so alternative approach should be designed if this causes performance
  // regressions and the stronger optimization should be re-implemented.
  NumberMatcher number_matcher(input);
  if (number_matcher.HasResolvedValue()) {
    DirectHandle<Object> num_obj =
        broker()
            ->local_isolate_or_isolate()
            ->factory()
            ->NewNumber<AllocationType::kOld>(number_matcher.ResolvedValue());
    Handle<String> num_str =
        broker()->local_isolate_or_isolate()->factory()->NumberToString(
            num_obj);
    Node* reduced = graph()->NewNode(
        common()->HeapConstant(broker()->CanonicalPersistentHandle(num_str)));

    ReplaceWithValue(node, reduced);
    return Replace(reduced);
  }

  return NoChange();
}

// Return a String from {node}, which should be either a HeapConstant<String>
// (in which case we return the String), or a number (in which case we convert
// it to a String).
Handle<String> JSNativeContextSpecialization::CreateStringConstant(Node* node) {
  DCHECK(IrOpcode::IsConstantOpcode(node->opcode()));
  NumberMatcher number_matcher(node);
  if (number_matcher.HasResolvedValue()) {
    DirectHandle<Object> num_obj =
        broker()
            ->local_isolate_or_isolate()
            ->factory()
            ->NewNumber<AllocationType::kOld>(number_matcher.ResolvedValue());
    // Note that we do not store the result of NumberToString in
    // {created_strings_}, because the latter is used to know if strings are
    // safe to be used in the background, but we always have as additional
    // information the node from which the string was created ({node} is that
    // case), and if this node is a kHeapNumber, then we know that we must have
    // created the string, and that there it is safe to read. So, we don't need
    // {created_strings_} in that case.
    return broker()->local_isolate_or_isolate()->factory()->NumberToString(
        num_obj);
  } else {
    HeapObjectMatcher matcher(node);
    if (matcher.HasResolvedValue() && matcher.Ref(broker()).IsString()) {
      return matcher.Ref(broker()).AsString().object();
    } else {
      UNREACHABLE();
    }
  }
}

namespace {
bool IsStringConstant(JSHeapBroker* broker, Node* node) {
  HeapObjectMatcher matcher(node);
  return matcher.HasResolvedValue() && matcher.Ref(broker).IsString();
}

bool IsStringWithNonAccessibleContent(JSHeapBroker* broker, Node* node) {
  HeapObjectMatcher matcher(node);
  if (matcher.HasResolvedValue() && matcher.Ref(broker).IsString()) {
    StringRef input = matcher.Ref(broker).AsString();
    return !input.IsContentAccessible();
  }
  return false;
}
}  // namespace

Reduction JSNativeContextSpecialization::ReduceJSAsyncFunctionEnter(
    Node* node) {
  DCHECK_EQ(IrOpcode::kJSAsyncFunctionEnter, node->opcode());
  Node* closure = NodeProperties::GetValueInput(node, 0);
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Node* context = NodeProperties::GetContextInput(node);
  Node* frame_state = NodeProperties::GetFrameStateInput(node);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  if (!dependencies()->DependOnPromiseHookProtector()) return NoChange();

  // Create the promise for the async function.
  Node* promise = effect =
      graph()->NewNode(javascript()->CreatePromise(), context, effect);

  // Create the JSAsyncFunctionObject based on the SharedFunctionInfo
  // extracted from the top-most frame in {frame_state}.
  SharedFunctionInfoRef shared = MakeRef(
      broker(),
      FrameStateInfoOf(frame_state->op()).shared_info().ToHandleChecked());
  DCHECK(shared.is_compiled());
  int register_count =
      shared.internal_formal_parameter_count_without_receiver() +
      shared.GetBytecodeArray(broker()).register_count();
  MapRef fixed_array_map = broker()->fixed_array_map();
  AllocationBuilder ab(jsgraph(), broker(), effect, control);
  if (!ab.CanAllocateArray(register_count, fixed_array_map)) {
    return NoChange();
  }
  Node* value = effect =
      graph()->NewNode(javascript()->CreateAsyncFunctionObject(register_count),
                       closure, receiver, promise, context, effect, control);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSNativeContextSpecialization::ReduceJSAsyncFunctionReject(
    Node* node) {
  DCHECK_EQ(IrOpcode::kJSAsyncFunctionReject, node->opcode());
  Node* async_function_object = NodeProperties::GetValueInput(node, 0);
  Node* reason = NodeProperties::GetValueInput(node, 1);
  Node* context = NodeProperties::GetContextInput(node);
  Node* frame_state = NodeProperties::GetFrameStateInput(node);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  if (!dependencies()->DependOnPromiseHookProtector()) return NoChange();

  // Load the promise from the {async_function_object}.
  Node* promise = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSAsyncFunctionObjectPromise()),
      async_function_object, effect, control);

  // Create a nested frame state inside the current method's most-recent
  // {frame_state} that will ensure that lazy deoptimizations at this
  // point will still return the {promise} instead of the result of the
  // JSRejectPromise operation (which yields undefined).
  Node* parameters[] = {promise};
  frame_state = CreateStubBuiltinContinuationFrameState(
      jsgraph(), Builtin::kAsyncFunctionLazyDeoptContinuation, context,
      parameters, arraysize(parameters), frame_state,
      ContinuationFrameStateMode::LAZY);

  // Disable the additional debug event for the rejection since a
  // debug event already happend for the exception that got us here.
  Node* debug_event = jsgraph()->FalseConstant();
  effect = graph()->NewNode(javascript()->RejectPromise(), promise, reason,
                            debug_event, context, frame_state, effect, control);
  ReplaceWithValue(node, promise, effect, control);
  return Replace(promise);
}

Reduction JSNativeContextSpecialization::ReduceJSAsyncFunctionResolve(
    Node* node) {
  DCHECK_EQ(IrOpcode::kJSAsyncFunctionResolve, node->opcode());
  Node* async_function_object = NodeProperties::GetValueInput(node, 0);
  Node* value = NodeProperties::GetValueInput(node, 1);
  Node* context = NodeProperties::GetContextInput(node);
  Node* frame_state = NodeProperties::GetFrameStateInput(node);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  if (!dependencies()->DependOnPromiseHookProtector()) return NoChange();

  // Load the promise from the {async_function_object}.
  Node* promise = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSAsyncFunctionObjectPromise()),
      async_function_object, effect, control);

  // Create a nested frame state inside the current method's most-recent
  // {frame_state} that will ensure that lazy deoptimizations at this
  // point will still return the {promise} instead of the result of the
  // JSResolvePromise operation (which yields undefined).
  Node* parameters[] = {promise};
  frame_state = CreateStubBuiltinContinuationFrameState(
      jsgraph(), Builtin::kAsyncFunctionLazyDeoptContinuation, context,
      parameters, arraysize(parameters), frame_state,
      ContinuationFrameStateMode::LAZY);

  effect = graph()->NewNode(javascript()->ResolvePromise(), promise, value,
                            context, frame_state, effect, control);
  ReplaceWithValue(node, promise, effect, control);
  return Replace(promise);
}

// Concatenates {left} and {right}. The result is fairly similar to creating a
// new ConsString with {left} and {right} and then flattening it, which we don't
// do because String::Flatten does not support background threads. Rather than
// implementing a full String::Flatten for background threads, we prefered to
// implement this Concatenate function, which, unlike String::Flatten, doesn't
// need to replace ConsStrings by ThinStrings.
Handle<String> JSNativeContextSpecialization::Concatenate(
    Handle<String> left, Handle<String> right) {
  if (left->length() == 0) return right;
  if (right->length() == 0) return left;

  // Repeated concatenations have a quadratic cost (eg, "s+=a;s+=b;s+=c;...").
  // Rather than doing static analysis to determine how many concatenations we
  // there are and how many uses the result of each concatenation have, we
  // generate ConsString when the result of the concatenation would have more
  // than {kConstantStringFlattenMaxSize} characters, and flattened SeqString
  // otherwise.
  // TODO(dmercadier): ideally, we would like to get rid of this constant, and
  // always flatten. This requires some care to avoid the quadratic worst-case.
  constexpr int32_t kConstantStringFlattenMaxSize = 100;

  int32_t length = left->length() + right->length();
  if (length > kConstantStringFlattenMaxSize) {
    // The generational write-barrier doesn't work in background threads, so,
    // if {left} or {right} are in the young generation, we would have to copy
    // them to the local heap (which is old) before creating the (old)
    // ConsString. But, copying a ConsString instead of flattening it to a
    // SeqString makes no sense here (since flattening would be faster and use
    // less memory). Thus, if one of {left} or {right} is a young string, we'll
    // build a SeqString rather than a ConsString, regardless of {length}.
    // TODO(dmercadier, dinfuehr): always build a ConsString here once the
    // generational write-barrier supports background threads.
    if (!LocalHeap::Current() || (!HeapLayout::InYoungGeneration(*left) &&
                                  !HeapLayout::InYoungGeneration(*right))) {
      return broker()
          ->local_isolate_or_isolate()
          ->factory()
          ->NewConsString(left, right, AllocationType::kOld)
          .ToHandleChecked();
    }
  }

  // If one of the string is not in readonly space, then we need a
  // SharedStringAccessGuardIfNeeded before accessing its content.
  bool require_guard = SharedStringAccessGuardIfNeeded::IsNeeded(
                           *left, broker()->local_isolate_or_isolate()) ||
                       SharedStringAccessGuardIfNeeded::IsNeeded(
                           *right, broker()->local_isolate_or_isolate());
  SharedStringAccessGuardIfNeeded access_guard(
      require_guard ? broker()->local_isolate_or_isolate() : nullptr);

  if (left->IsOneByteRepresentation() && right->IsOneByteRepresentation()) {
    // {left} and {right} are 1-byte ==> the result will be 1-byte.
    // Note that we need a canonical handle, because we insert in
    // {created_strings_} the handle's address, which is kinda meaningless if
    // the handle isn't canonical.
    Handle<SeqOneByteString> flat = broker()->CanonicalPersistentHandle(
        broker()
            ->local_isolate_or_isolate()
            ->factory()
            ->NewRawOneByteString(length, AllocationType::kOld)
            .ToHandleChecked());
    created_strings_.insert(flat);
    DisallowGarbageCollection no_gc;
    String::WriteToFlat(*left, flat->GetChars(no_gc, access_guard), 0,
                        left->length(), access_guard);
    String::WriteToFlat(*right,
                        flat->GetChars(no_gc, access_guard) + left->length(), 0,
                        right->length(), access_guard);
    return flat;
  } else {
    // One (or both) of {left} and {right} is 2-byte ==> the result will be
    // 2-byte.
    Handle<SeqTwoByteString> flat = broker()->CanonicalPersistentHandle(
        broker()
            ->local_isolate_or_isolate()
            ->factory()
            ->NewRawTwoByteString(length, AllocationType::kOld)
            .ToHandleChecked());
    created_strings_.insert(flat);
    DisallowGarbageCollection no_gc;
    String::WriteToFlat(*left, flat->GetChars(no_gc, access_guard), 0,
                        left->length(), access_guard);
    String::WriteToFlat(*right,
                        flat->GetChars(no_gc, access_guard) + left->length(), 0,
                        right->length(), access_guard);
    return flat;
  }
}

bool JSNativeContextSpecialization::StringCanSafelyBeRead(Node* const node,
                                                          Handle<String> str) {
  DCHECK(node->opcode() == IrOpcode::kHeapConstant ||
         node->opcode() == IrOpcode::kNumberConstant);
  if (broker()->IsMainThread()) {
    // All strings are safe to be read on the main thread.
    return true;
  }
  if (node->opcode() == IrOpcode::kNumberConstant) {
    // If {node} is a number constant, then {str} is the stringification of this
    // number which we must have created ourselves.
    return true;
  }
  return !IsStringWithNonAccessibleContent(broker(), node) ||
         created_strings_.find(str) != created_strings_.end();
}

Reduction JSNativeContextSpecialization::ReduceJSAdd(Node* node) {
  // TODO(turbofan): This has to run together with the inlining and
  // native context specialization to be able to leverage the string
  // constant-folding for optimizing property access, but we should
  // nevertheless find a better home for this at some point.
  DCHECK_EQ(IrOpcode::kJSAdd, node->opcode());

  Node* const lhs = node->InputAt(0);
  Node* const rhs = node->InputAt(1);

  std::optional<size_t> lhs_len = GetMaxStringLength(broker(), lhs);
  std::optional<size_t> rhs_len = GetMaxStringLength(broker(), rhs);
  if (!lhs_len || !rhs_len) return NoChange();

  // Fold if at least one of the parameters is a string constant and the
  // addition won't throw due to too long result.
  if (*lhs_len + *rhs_len <= String::kMaxLength &&
      (IsStringConstant(broker(), lhs) || IsStringConstant(broker(), rhs))) {
    // We need canonical handles for {left} and {right}, in order to be able to
    // search {created_strings_} if needed.
    Handle<String> left =
        broker()->CanonicalPersistentHandle(CreateStringConstant(lhs));
    Handle<String> right =
        broker()->CanonicalPersistentHandle(CreateStringConstant(rhs));

    if (!(StringCanSafelyBeRead(lhs, left) &&
          StringCanSafelyBeRead(rhs, right))) {
      // One of {lhs} or {rhs} is not safe to be read in the background.

      if (left->length() + right->length() > ConsString::kMinLength &&
          (!LocalHeap::Current() || (!HeapLayout::InYoungGeneration(*left) &&
                                     !HeapLayout::InYoungGeneration(*right)))) {
        // We can create a ConsString with {left} and {right}, without needing
        // to read their content (and this ConsString will not introduce
        // old-to-new pointers from the background).
        Handle<String> concatenated =
            broker()
                ->local_isolate_or_isolate()
                ->factory()
                ->NewConsString(left, right, AllocationType::kOld)
                .ToHandleChecked();
        Node* reduced = graph()->NewNode(common()->HeapConstant(
            broker()->CanonicalPersistentHandle(concatenated)));
        ReplaceWithValue(node, reduced);
        return Replace(reduced);
      } else {
        // Concatenating those strings would not produce a ConsString but rather
        // a flat string (because the result is small). And, since the strings
        // are not safe to be read in the background, this wouldn't be safe.
        // Or, one of the string is in the young generation, and since the
        // generational barrier doesn't support background threads, we cannot
        // create the ConsString.
        return NoChange();
      }
    }

    Handle<String> concatenated = Concatenate(left, right);
    Node* reduced = graph()->NewNode(common()->HeapConstant(
        broker()->CanonicalPersistentHandle(concatenated)));

    ReplaceWithValue(node, reduced);
    return Replace(reduced);
  }

  return NoChange();
}

Reduction JSNativeContextSpecialization::ReduceJSGetSuperConstructor(
    Node* node) {
  DCHECK_EQ(IrOpcode::kJSGetSuperConstructor, node->opcode());
  Node* constructor = NodeProperties::GetValueInput(node, 0);

  // Check if the input is a known JSFunction.
  HeapObjectMatcher m(constructor);
  if (!m.HasResolvedValue() || !m.Ref(broker()).IsJSFunction()) {
    return NoChange();
  }
  JSFunctionRef function = m.Ref(broker()).AsJSFunction();
  MapRef function_map = function.map(broker());
  HeapObjectRef function_prototype = function_map.prototype(broker());

  // We can constant-fold the super constructor access if the
  // {function}s map is stable, i.e. we can use a code dependency
  // to guard against [[Prototype]] changes of {function}.
  if (function_map.is_stable()) {
    dependencies()->DependOnStableMap(function_map);
    Node* value = jsgraph()->ConstantNoHole(function_prototype, broker());
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  return NoChange();
}

Reduction
JSNativeContextSpecialization::ReduceJSFindNonDefaultConstructorOrConstruct(
    Node* node) {
  JSFindNonDefaultConstructorOrConstructNode n(node);
  Node* this_function = n.this_function();
  Node* new_target = n.new_target();
  Node* effect = n.effect();
  Control control = n.control();

  // If the JSFindNonDefaultConstructorOrConstruct operation is inside a try
  // catch, wiring up the graph is complex (reason: if
  // JSFindNonDefaultConstructorOrConstruct reduces to a constant which is
  // something else than a default base ctor, it cannot throw an exception, and
  // the try-catch structure has to be rewired). As this use case is rare, give
  // up optimizing it here.
  if (NodeProperties::IsExceptionalCall(node)) {
    return NoChange();
  }

  // TODO(v8:13091): Don't produce incomplete stack traces when debug is active.
  // We already deopt when a breakpoint is set. But it would be even nicer to
  // avoid producting incomplete stack traces when when debug is active, even if
  // there are no breakpoints - then a user inspecting stack traces via Dev
  // Tools would always see the full stack trace.

  // Check if the input is a known JSFunction.
  HeapObjectMatcher m(this_function);
  if (!m.HasResolvedValue() || !m.Ref(broker()).IsJSFunction()) {
    return NoChange();
  }

  JSFunctionRef this_function_ref = m.Ref(broker()).AsJSFunction();
  MapRef function_map = this_function_ref.map(broker());
  HeapObjectRef current = function_map.prototype(broker());
  // The uppermost JSFunction on the class hierarchy (above it, there can be
  // other JSObjects, e.g., Proxies).
  OptionalJSObjectRef last_function;

  Node* return_value;
  Node* ctor_or_instance;

  // Walk the class inheritance tree until we find a ctor which is not a default
  // derived ctor.
  while (true) {
    if (!current.IsJSFunction()) {
      return NoChange();
    }
    JSFunctionRef current_function = current.AsJSFunction();

    // If there are class fields, bail out. TODO(v8:13091): Handle them here.
    if (current_function.shared(broker())
            .requires_instance_members_initializer()) {
      return NoChange();
    }

    // If there are private methods, bail out. TODO(v8:13091): Handle them here.
    if (current_function.context(broker())
            .scope_info(broker())
            .ClassScopeHasPrivateBrand()) {
      return NoChange();
    }

    FunctionKind kind = current_function.shared(broker()).kind();

    if (kind != FunctionKind::kDefaultDerivedConstructor) {
      // The hierarchy walk will end here; this is the last change to bail out
      // before creating new nodes.
      if (!dependencies()->DependOnArrayIteratorProtector()) {
        return NoChange();
      }
      last_function = current_function;

      if (kind == FunctionKind::kDefaultBaseConstructor) {
        return_value = jsgraph()->BooleanConstant(true);

        // Generate a builtin call for creating the instance.
        Node* constructor =
            jsgraph()->ConstantNoHole(current_function, broker());

        // In the current FrameState setup, the two outputs of this bytecode are
        // poked at indices slot(index(reg_2)) (boolean_output) and
        // slot(index(reg_2) + 1) (object_output). Now we're reducing this
        // bytecode to a builtin call which only has one output (object_output).
        // Change where in the FrameState the output is poked at.

        // The current poke location points to the location for boolean_ouput.
        // We move the poke location by -1, since the poke location decreases
        // when the register index increases (see
        // BytecodeGraphBuilder::Environment::BindRegistersToProjections).

        // The location for boolean_output is already hard-wired to true (which
        // is the correct value here) in
        // BytecodeGraphBuilder::VisitFindNonDefaultConstructorOrConstruct.

        FrameState old_frame_state = n.frame_state();
        auto old_poke_offset = old_frame_state.frame_state_info()
                                   .state_combine()
                                   .GetOffsetToPokeAt();
        FrameState new_frame_state = CloneFrameState(
            jsgraph(), old_frame_state,
            OutputFrameStateCombine::PokeAt(old_poke_offset - 1));

        effect = ctor_or_instance = graph()->NewNode(
            jsgraph()->javascript()->Create(), constructor, new_target,
            n.context(), new_frame_state, effect, control);
      } else {
        return_value = jsgraph()->BooleanConstant(false);
        ctor_or_instance =
            jsgraph()->ConstantNoHole(current_function, broker());
      }
      break;
    }

    // Keep walking up the class tree.
    current = current_function.map(broker()).prototype(broker());
  }

  dependencies()->DependOnStablePrototypeChain(
      function_map, WhereToStart::kStartAtReceiver, last_function);

  // Update the uses of {node}.
  for (Edge edge : node->use_edges()) {
    Node* const user = edge.from();
    if (NodeProperties::IsEffectEdge(edge)) {
      edge.UpdateTo(effect);
    } else if (NodeProperties::IsControlEdge(edge)) {
      edge.UpdateTo(control);
    } else {
      DCHECK(NodeProperties::IsValueEdge(edge));
      switch (ProjectionIndexOf(user->op())) {
        case 0:
          Replace(user, return_value);
          break;
        case 1:
          Replace(user, ctor_or_instance);
          break;
        default:
          UNREACHABLE();
      }
    }
  }
  node->Kill();
  return Replace(return_value);
}

Reduction JSNativeContextSpecialization::ReduceJSInstanceOf(Node* node) {
  JSInstanceOfNode n(node);
  FeedbackParameter const& p = n.Parameters();
  Node* object = n.left();
  Node* constructor = n.right();
  TNode<Object> context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  // Check if the right hand side is a known {receiver}, or
  // we have feedback from the InstanceOfIC.
  OptionalJSObjectRef receiver;
  HeapObjectMatcher m(constructor);
  if (m.HasResolvedValue() && m.Ref(broker()).IsJSObject()) {
    receiver = m.Ref(broker()).AsJSObject();
  } else if (p.feedback().IsValid()) {
    ProcessedFeedback const& feedback =
        broker()->GetFeedbackForInstanceOf(FeedbackSource(p.feedback()));
    if (feedback.IsInsufficient()) return NoChange();
    receiver = feedback.AsInstanceOf().value();
  } else {
    return NoChange();
  }

  if (!receiver.has_value()) return NoChange();

  MapRef receiver_map = receiver->map(broker());
  NameRef name = broker()->has_instance_symbol();
  PropertyAccessInfo access_info =
      broker()->GetPropertyAccessInfo(receiver_map, name, AccessMode::kLoad);

  // TODO(v8:11457) Support dictionary mode holders here.
  if (access_info.IsInvalid() || access_info.HasDictionaryHolder()) {
    return NoChange();
  }
  access_info.RecordDependencies(dependencies());

  PropertyAccessBuilder access_builder(jsgraph(), broker());

  if (access_info.IsNotFound()) {
    // If there's no @@hasInstance handler, the OrdinaryHasInstance operation
    // takes over, but that requires the constructor to be callable.
    if (!receiver_map.is_callable()) return NoChange();

    dependencies()->DependOnStablePrototypeChains(
        access_info.lookup_start_object_maps(), kStartAtPrototype);

    // Monomorphic property access.
    access_builder.BuildCheckMaps(constructor, &effect, control,
                                  access_info.lookup_start_object_maps());

    // Lower to OrdinaryHasInstance(C, O).
    NodeProperties::ReplaceValueInput(node, constructor, 0);
    NodeProperties::ReplaceValueInput(node, object, 1);
    NodeProperties::ReplaceEffectInput(node, effect);
    static_assert(n.FeedbackVectorIndex() == 2);
    node->RemoveInput(n.FeedbackVectorIndex());
    NodeProperties::ChangeOp(node, javascript()->OrdinaryHasInstance());
    return Changed(node).FollowedBy(ReduceJSOrdinaryHasInstance(node));
  }

  if (access_info.IsFastDataConstant()) {
    OptionalJSObjectRef holder = access_info.holder();
    bool found_on_proto = holder.has_value();
    JSObjectRef holder_ref = found_on_proto ? holder.value() : receiver.value();
    if (access_info.field_representation().IsDouble()) return NoChange();
    OptionalObjectRef constant = holder_ref.GetOwnFastConstantDataProperty(
        broker(), access_info.field_representation(), access_info.field_index(),
        dependencies());
    if (!constant.has_value() || !constant->IsHeapObject() ||
        !constant->AsHeapObject().map(broker()).is_callable()) {
      return NoChange();
    }

    if (found_on_proto) {
      dependencies()->DependOnStablePrototypeChains(
          access_info.lookup_start_object_maps(), kStartAtPrototype,
          holder.value());
    }

    // Check that {constructor} is actually {receiver}.
    constructor = access_builder.BuildCheckValue(constructor, &effect, control,
                                                 *receiver);

    // Monomorphic property access.
    access_builder.BuildCheckMaps(constructor, &effect, control,
                                  access_info.lookup_start_object_maps());

    // Create a nested frame state inside the current method's most-recent frame
    // state that will ensure that deopts that happen after this point will not
    // fallback to the last Checkpoint--which would completely re-execute the
    // instanceof logic--but rather create an activation of a version of the
   
"""


```