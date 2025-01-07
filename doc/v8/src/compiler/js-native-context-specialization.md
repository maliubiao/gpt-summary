Response: The user wants a summary of the C++ code file `v8/src/compiler/js-native-context-specialization.cc`.
This is part 1 of 3, suggesting a focus on the initial functionalities.

The file name hints at its purpose: specializing JavaScript operations based on the native context. This likely involves optimizing common JavaScript patterns by leveraging information about the global scope and built-in objects.

Based on the included headers and the `Reduce` function with its many `case` statements, the file seems to implement an advanced reducer in the Turbofan compiler pipeline. It looks for specific JavaScript operations (like `JSAdd`, `JSLoadGlobal`, etc.) in the intermediate representation (IR) graph and attempts to simplify or replace them with more efficient lower-level operations.

The file also contains helper functions like `GetMaxStringLength`, `CreateStringConstant`, and `Concatenate`, which suggests optimizations related to string manipulation.

The class `JSNativeContextSpecialization` holds the core logic. It seems to rely heavily on `JSHeapBroker` to access information about the JavaScript heap and `CompilationDependencies` to manage dependencies for deoptimization.

In summary, this part of the file likely sets up the framework for native context specialization. It initializes the reducer and implements reductions for a subset of JavaScript operations, focusing on constant folding and simple optimizations based on the native context.
这个C++源代码文件（`v8/src/compiler/js-native-context-specialization.cc`）的主要功能是**在V8的Turbofan编译器中，基于当前的Native Context（原生上下文）来优化JavaScript代码的执行**。

更具体地说，这个文件实现了一个编译器优化阶段，它会检查程序中的特定JavaScript操作，并尝试利用关于全局对象、内置对象以及其他与Native Context相关的信息来：

1. **简化操作**: 例如，如果知道一个加法操作的其中一个操作数是字符串常量，并且结果字符串的长度在限制之内，它可以直接计算出结果字符串，从而避免运行时的字符串拼接。
2. **替换为更高效的操作**: 某些JavaScript操作可以通过更底层的、更高效的Turbofan节点来表示。
3. **添加依赖**: 为了保证优化的正确性，它会记录一些依赖关系。如果运行时的状态违反了这些依赖，那么代码可能会被去优化（deoptimize）。

由于这是第1部分，我们可以推断这部分主要集中在：

* **基础架构的建立**: 定义了 `JSNativeContextSpecialization` 类，它继承自 `AdvancedReducer`，并包含了必要的成员变量，如 `JSGraph`、`JSHeapBroker` 和 `CompilationDependencies`。
* **初步的优化规则**:  `Reduce` 函数通过 `switch` 语句处理多种 JavaScript 操作符，并调用相应的 `ReduceJS...` 函数来实现特定的优化。  目前看到的 `case` 包括了基本的算术运算 (`kJSAdd`)、异步函数处理 (`kJSAsyncFunctionEnter`, `kJSAsyncFunctionReject`, `kJSAsyncFunctionResolve`)、原型链相关的操作 (`kJSGetSuperConstructor`, `kJSInstanceOf`, `kJSHasInPrototypeChain`, `kJSOrdinaryHasInstance`)、Promise相关的操作 (`kJSPromiseResolve`, `kJSResolvePromise`) 以及全局变量的加载和存储 (`kJSLoadGlobal`, `kJSStoreGlobal`) 和属性访问相关的操作 (`kJSLoadNamed`, `kJSLoadNamedFromSuper`, `kJSSetNamedProperty`, `kJSHasProperty`, `kJSLoadProperty`, `kJSSetKeyedProperty`, `kJSDefineKeyedOwnProperty`, `kJSDefineNamedOwnProperty`, `kJSDefineKeyedOwnPropertyInLiteral`, `kJSStoreInArrayLiteral`) 和类型转换 (`kJSToObject`, `kJSToString`) 和迭代器 (`kJSGetIterator`)。
* **一些辅助函数**: 例如，`GetMaxStringLength` 用于判断是否可以将一个节点安全地转换为字符串并获取其最大长度，`CreateStringConstant` 用于创建一个字符串常量节点， `Concatenate` 用于在编译时连接两个字符串常量。

**与 JavaScript 的功能关系以及 JavaScript 示例：**

这个文件中的代码直接影响 JavaScript 代码的执行效率。它尝试在编译时执行一些 JavaScript 的逻辑，或者将一些高层次的 JavaScript 操作转换为更底层的操作。

**示例：`ReduceJSAdd(Node* node)` 和字符串连接**

当 JavaScript 中进行字符串相加时，例如：

```javascript
const str1 = "hello";
const str2 = " world";
const result = str1 + str2;
```

`ReduceJSAdd` 函数会尝试识别 `kJSAdd` 操作，并且如果 `str1` 和 `str2` 都是字符串常量，并且它们的长度之和没有超过限制，那么编译器可以直接在编译时将它们连接起来，生成一个包含 `"hello world"` 的字符串常量节点，而不是生成运行时的字符串连接代码。这样可以显著提高性能。

**示例：`ReduceJSLoadGlobal(Node* node)` 和全局变量访问**

当 JavaScript 代码访问全局变量时，例如：

```javascript
console.log("Hello");
```

`ReduceJSLoadGlobal` 函数会尝试优化对全局变量 `console` 的访问。如果反馈信息表明 `console` 绑定到一个特定的全局对象属性，并且这个属性是不可变的，那么编译器可以直接将 `console` 的值嵌入到生成的代码中，避免运行时的查找。

总而言之，这个文件的第1部分主要负责构建基于 Native Context 的代码优化的基础框架，并实现了一部分核心的优化规则，旨在提升 V8 引擎执行 JavaScript 代码的效率。

Prompt: 
```
这是目录为v8/src/compiler/js-native-context-specialization.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

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
    // ToBoolean stub that finishes the remaining work of instanceof and returns
    // to the caller without duplicating side-effects upon a lazy deopt.
    Node* continuation_frame_state = CreateStubBuiltinContinuationFrameState(
        jsgraph(), Builtin::kToBooleanLazyDeoptContinuation, context, nullptr,
        0, frame_state, ContinuationFrameStateMode::LAZY);

    // Call the @@hasInstance handler.
    Node* target = jsgraph()->ConstantNoHole(*constant, broker());
    Node* feedback = jsgraph()->UndefinedConstant();
    // Value inputs plus context, frame state, effect, control.
    static_assert(JSCallNode::ArityForArgc(1) + 4 == 8);
    node->EnsureInputCount(graph()->zone(), 8);
    node->ReplaceInput(JSCallNode::TargetIndex(), target);
    node->ReplaceInput(JSCallNode::ReceiverIndex(), constructor);
    node->ReplaceInput(JSCallNode::ArgumentIndex(0), object);
    node->ReplaceInput(3, feedback);
    node->ReplaceInput(4, context);
    node->ReplaceInput(5, continuation_frame_state);
    node->ReplaceInput(6, effect);
    node->ReplaceInput(7, control);
    NodeProperties::ChangeOp(
        node, javascript()->Call(JSCallNode::ArityForArgc(1), CallFrequency(),
                                 FeedbackSource(),
                                 ConvertReceiverMode::kNotNullOrUndefined));

    // Rewire the value uses of {node} to ToBoolean conversion of the result.
    Node* value = graph()->NewNode(simplified()->ToBoolean(), node);
    for (Edge edge : node->use_edges()) {
      if (NodeProperties::IsValueEdge(edge) && edge.from() != value) {
        edge.UpdateTo(value);
        Revisit(edge.from());
      }
    }
    return Changed(node);
  }

  return NoChange();
}

JSNativeContextSpecialization::InferHasInPrototypeChainResult
JSNativeContextSpecialization::InferHasInPrototypeChain(
    Node* receiver, Effect effect, HeapObjectRef prototype) {
  ZoneRefSet<Map> receiver_maps;
  NodeProperties::InferMapsResult result = NodeProperties::InferMapsUnsafe(
      broker(), receiver, effect, &receiver_maps);
  if (result == NodeProperties::kNoMaps) return kMayBeInPrototypeChain;

  ZoneVector<MapRef> receiver_map_refs(zone());

  // Try to determine either that all of the {receiver_maps} have the given
  // {prototype} in their chain, or that none do. If we can't tell, return
  // kMayBeInPrototypeChain.
  bool all = true;
  bool none = true;
  for (MapRef map : receiver_maps) {
    receiver_map_refs.push_back(map);
    if (result == NodeProperties::kUnreliableMaps && !map.is_stable()) {
      return kMayBeInPrototypeChain;
    }
    while (true) {
      if (IsSpecialReceiverInstanceType(map.instance_type())) {
        return kMayBeInPrototypeChain;
      }
      if (!map.IsJSObjectMap()) {
        all = false;
        break;
      }
      HeapObjectRef map_prototype = map.prototype(broker());
      if (map_prototype.equals(prototype)) {
        none = false;
        break;
      }
      map = map_prototype.map(broker());
      // TODO(v8:11457) Support dictionary mode protoypes here.
      if (!map.is_stable() || map.is_dictionary_map()) {
        return kMayBeInPrototypeChain;
      }
      if (map.oddball_type(broker()) == OddballType::kNull) {
        all = false;
        break;
      }
    }
  }
  DCHECK_IMPLIES(all, !none);
  if (!all && !none) return kMayBeInPrototypeChain;

  {
    OptionalJSObjectRef last_prototype;
    if (all) {
      // We don't need to protect the full chain if we found the prototype, we
      // can stop at {prototype}.  In fact we could stop at the one before
      // {prototype} but since we're dealing with multiple receiver maps this
      // might be a different object each time, so it's much simpler to include
      // {prototype}. That does, however, mean that we must check {prototype}'s
      // map stability.
      if (!prototype.IsJSObject() || !prototype.map(broker()).is_stable()) {
        return kMayBeInPrototypeChain;
      }
      last_prototype = prototype.AsJSObject();
    }
    WhereToStart start = result == NodeProperties::kUnreliableMaps
                             ? kStartAtReceiver
                             : kStartAtPrototype;
    dependencies()->DependOnStablePrototypeChains(receiver_map_refs, start,
                                                  last_prototype);
  }

  DCHECK_EQ(all, !none);
  return all ? kIsInPrototypeChain : kIsNotInPrototypeChain;
}

Reduction JSNativeContextSpecialization::ReduceJSHasInPrototypeChain(
    Node* node) {
  DCHECK_EQ(IrOpcode::kJSHasInPrototypeChain, node->opcode());
  Node* value = NodeProperties::GetValueInput(node, 0);
  Node* prototype = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};

  // Check if we can constant-fold the prototype chain walk
  // for the given {value} and the {prototype}.
  HeapObjectMatcher m(prototype);
  if (m.HasResolvedValue()) {
    InferHasInPrototypeChainResult result =
        InferHasInPrototypeChain(value, effect, m.Ref(broker()));
    if (result != kMayBeInPrototypeChain) {
      Node* result_in_chain =
          jsgraph()->BooleanConstant(result == kIsInPrototypeChain);
      ReplaceWithValue(node, result_in_chain);
      return Replace(result_in_chain);
    }
  }

  return NoChange();
}

Reduction JSNativeContextSpecialization::ReduceJSOrdinaryHasInstance(
    Node* node) {
  DCHECK_EQ(IrOpcode::kJSOrdinaryHasInstance, node->opcode());
  Node* constructor = NodeProperties::GetValueInput(node, 0);
  Node* object = NodeProperties::GetValueInput(node, 1);

  // Check if the {constructor} is known at compile time.
  HeapObjectMatcher m(constructor);
  if (!m.HasResolvedValue()) return NoChange();

  if (m.Ref(broker()).IsJSBoundFunction()) {
    // OrdinaryHasInstance on bound functions turns into a recursive invocation
    // of the instanceof operator again.
    JSBoundFunctionRef function = m.Ref(broker()).AsJSBoundFunction();
    Node* feedback = jsgraph()->UndefinedConstant();
    NodeProperties::ReplaceValueInput(node, object,
                                      JSInstanceOfNode::LeftIndex());
    NodeProperties::ReplaceValueInput(
        node,
        jsgraph()->ConstantNoHole(function.bound_target_function(broker()),
                                  broker()),
        JSInstanceOfNode::RightIndex());
    node->InsertInput(zone(), JSInstanceOfNode::FeedbackVectorIndex(),
                      feedback);
    NodeProperties::ChangeOp(node, javascript()->InstanceOf(FeedbackSource()));
    return Changed(node).FollowedBy(ReduceJSInstanceOf(node));
  }

  if (m.Ref(broker()).IsJSFunction()) {
    // Optimize if we currently know the "prototype" property.

    JSFunctionRef function = m.Ref(broker()).AsJSFunction();

    // TODO(neis): Remove the has_prototype_slot condition once the broker is
    // always enabled.
    if (!function.map(broker()).has_prototype_slot() ||
        !function.has_instance_prototype(broker()) ||
        function.PrototypeRequiresRuntimeLookup(broker())) {
      return NoChange();
    }

    HeapObjectRef prototype =
        dependencies()->DependOnPrototypeProperty(function);
    Node* prototype_constant = jsgraph()->ConstantNoHole(prototype, broker());

    // Lower the {node} to JSHasInPrototypeChain.
    NodeProperties::ReplaceValueInput(node, object, 0);
    NodeProperties::ReplaceValueInput(node, prototype_constant, 1);
    NodeProperties::ChangeOp(node, javascript()->HasInPrototypeChain());
    return Changed(node).FollowedBy(ReduceJSHasInPrototypeChain(node));
  }

  return NoChange();
}

// ES section #sec-promise-resolve
Reduction JSNativeContextSpecialization::ReduceJSPromiseResolve(Node* node) {
  DCHECK_EQ(IrOpcode::kJSPromiseResolve, node->opcode());
  Node* constructor = NodeProperties::GetValueInput(node, 0);
  Node* value = NodeProperties::GetValueInput(node, 1);
  Node* context = NodeProperties::GetContextInput(node);
  FrameState frame_state{NodeProperties::GetFrameStateInput(node)};
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  // Check if the {constructor} is the %Promise% function.
  HeapObjectMatcher m(constructor);
  if (!m.HasResolvedValue() ||
      !m.Ref(broker()).equals(native_context().promise_function(broker()))) {
    return NoChange();
  }

  // Only optimize if {value} cannot be a JSPromise.
  MapInference inference(broker(), value, effect);
  if (!inference.HaveMaps() ||
      inference.AnyOfInstanceTypesAre(JS_PROMISE_TYPE)) {
    return NoChange();
  }

  if (!dependencies()->DependOnPromiseHookProtector()) return NoChange();

  // Create a %Promise% instance and resolve it with {value}.
  Node* promise = effect =
      graph()->NewNode(javascript()->CreatePromise(), context, effect);

  // Create a nested frame state inside the current method's most-recent
  // {frame_state} that will ensure that lazy deoptimizations at this
  // point will still return the {promise} instead of the result of the
  // ResolvePromise operation (which yields undefined).
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

// ES section #sec-promise-resolve-functions
Reduction JSNativeContextSpecialization::ReduceJSResolvePromise(Node* node) {
  DCHECK_EQ(IrOpcode::kJSResolvePromise, node->opcode());
  Node* promise = NodeProperties::GetValueInput(node, 0);
  Node* resolution = NodeProperties::GetValueInput(node, 1);
  Node* context = NodeProperties::GetContextInput(node);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  // Check if we know something about the {resolution}.
  MapInference inference(broker(), resolution, effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& resolution_maps = inference.GetMaps();

  // Compute property access info for "then" on {resolution}.
  ZoneVector<PropertyAccessInfo> access_infos(graph()->zone());
  AccessInfoFactory access_info_factory(broker(), graph()->zone());

  for (MapRef map : resolution_maps) {
    access_infos.push_back(broker()->GetPropertyAccessInfo(
        map, broker()->then_string(), AccessMode::kLoad));
  }
  PropertyAccessInfo access_info =
      access_info_factory.FinalizePropertyAccessInfosAsOne(access_infos,
                                                           AccessMode::kLoad);

  // TODO(v8:11457) Support dictionary mode prototypes here.
  if (access_info.IsInvalid() || access_info.HasDictionaryHolder()) {
    return inference.NoChange();
  }

  // Only optimize when {resolution} definitely doesn't have a "then" property.
  if (!access_info.IsNotFound()) return inference.NoChange();

  if (!inference.RelyOnMapsViaStability(dependencies())) {
    return inference.NoChange();
  }

  dependencies()->DependOnStablePrototypeChains(
      access_info.lookup_start_object_maps(), kStartAtPrototype);

  // Simply fulfill the {promise} with the {resolution}.
  Node* value = effect =
      graph()->NewNode(javascript()->FulfillPromise(), promise, resolution,
                       context, effect, control);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

namespace {

FieldAccess ForPropertyCellValue(MachineRepresentation representation,
                                 Type type, OptionalMapRef map, NameRef name) {
  WriteBarrierKind kind = kFullWriteBarrier;
  if (representation == MachineRepresentation::kTaggedSigned) {
    kind = kNoWriteBarrier;
  } else if (representation == MachineRepresentation::kTaggedPointer) {
    kind = kPointerWriteBarrier;
  }
  MachineType r = MachineType::TypeForRepresentation(representation);
  FieldAccess access = {
      kTaggedBase, PropertyCell::kValueOffset, name.object(), map, type, r,
      kind, "PropertyCellValue"};
  return access;
}

}  // namespace

// TODO(neis): Try to merge this with ReduceNamedAccess by introducing a new
// PropertyAccessInfo kind for global accesses and using the existing mechanism
// for building loads/stores.
// Note: The "receiver" parameter is only used for DCHECKS, but that's on
// purpose. This way we can assert the super property access cases won't hit the
// code which hasn't been modified to support super property access.
Reduction JSNativeContextSpecialization::ReduceGlobalAccess(
    Node* node, Node* lookup_start_object, Node* receiver, Node* value,
    NameRef name, AccessMode access_mode, Node* key,
    PropertyCellRef property_cell, Node* effect) {
  if (!property_cell.Cache(broker())) {
    TRACE_BROKER_MISSING(broker(), "usable data for " << property_cell);
    return NoChange();
  }

  ObjectRef property_cell_value = property_cell.value(broker());
  if (property_cell_value.IsPropertyCellHole()) {
    // The property cell is no longer valid.
    return NoChange();
  }

  PropertyDetails property_details = property_cell.property_details();
  PropertyCellType property_cell_type = property_details.cell_type();
  DCHECK_EQ(PropertyKind::kData, property_details.kind());

  Node* control = NodeProperties::GetControlInput(node);
  if (effect == nullptr) {
    effect = NodeProperties::GetEffectInput(node);
  }

  // We have additional constraints for stores.
  if (access_mode == AccessMode::kStore) {
    DCHECK_EQ(receiver, lookup_start_object);
    if (property_details.IsReadOnly()) {
      // Don't even bother trying to lower stores to read-only data properties.
      // TODO(neis): We could generate code that checks if the new value equals
      // the old one and then does nothing or deopts, respectively.
      return NoChange();
    } else if (property_cell_type == PropertyCellType::kUndefined) {
      return NoChange();
    } else if (property_cell_type == PropertyCellType::kConstantType) {
      // We rely on stability further below.
      if (property_cell_value.IsHeapObject() &&
          !property_cell_value.AsHeapObject().map(broker()).is_stable()) {
        return NoChange();
      }
    }
  } else if (access_mode == AccessMode::kHas) {
    DCHECK_EQ(receiver, lookup_start_object);
    // has checks cannot follow the fast-path used by loads when these
    // conditions hold.
    if ((property_details.IsConfigurable() || !property_details.IsReadOnly()) &&
        property_details.cell_type() != PropertyCellType::kConstant &&
        property_details.cell_type() != PropertyCellType::kUndefined)
      return NoChange();
  }

  // Ensure that {key} matches the specified {name} (if {key} is given).
  if (key != nullptr) {
    effect = BuildCheckEqualsName(name, key, effect, control);
  }

  // If we have a {lookup_start_object} to validate, we do so by checking that
  // its map is the (target) global proxy's map. This guarantees that in fact
  // the lookup start object is the global proxy.
  // Note: we rely on the map constant below being the same as what is used in
  // NativeContextRef::GlobalIsDetached().
  if (lookup_start_object != nullptr) {
    effect = graph()->NewNode(
        simplified()->CheckMaps(
            CheckMapsFlag::kNone,
            ZoneRefSet<Map>(
                native_context().global_proxy_object(broker()).map(broker()))),
        lookup_start_object, effect, control);
  }

  if (access_mode == AccessMode::kLoad || access_mode == AccessMode::kHas) {
    // Load from non-configurable, read-only data property on the global
    // object can be constant-folded, even without deoptimization support.
    if (!property_details.IsConfigurable() && property_details.IsReadOnly()) {
      value = access_mode == AccessMode::kHas
                  ? jsgraph()->TrueConstant()
                  : jsgraph()->ConstantNoHole(property_cell_value, broker());
    } else {
      // Record a code dependency on the cell if we can benefit from the
      // additional feedback, or the global property is configurable (i.e.
      // can be deleted or reconfigured to an accessor property).
      if (property_details.cell_type() != PropertyCellType::kMutable ||
          property_details.IsConfigurable()) {
        dependencies()->DependOnGlobalProperty(property_cell);
      }

      // Load from constant/undefined global property can be constant-folded.
      if (property_details.cell_type() == PropertyCellType::kConstant ||
          property_details.cell_type() == PropertyCellType::kUndefined) {
        value = access_mode == AccessMode::kHas
                    ? jsgraph()->TrueConstant()
                    : jsgraph()->ConstantNoHole(property_cell_value, broker());
        DCHECK(!property_cell_value.IsHeapObject() ||
               !property_cell_value.IsPropertyCellHole());
      } else {
        DCHECK_NE(AccessMode::kHas, access_mode);

        // Load from constant type cell can benefit from type feedback.
        OptionalMapRef map;
        Type property_cell_value_type = Type::NonInternal();
        MachineRepresentation representation = MachineRepresentation::kTagged;
        if (property_details.cell_type() == PropertyCellType::kConstantType) {
          // Compute proper type based on the current value in the cell.
          if (property_cell_value.IsSmi()) {
            property_cell_value_type = Type::SignedSmall();
            representation = MachineRepresentation::kTaggedSigned;
          } else if (property_cell_value.IsHeapNumber()) {
            property_cell_value_type = Type::Number();
            representation = MachineRepresentation::kTaggedPointer;
          } else {
            MapRef property_cell_value_map =
                property_cell_value.AsHeapObject().map(broker());
            property_cell_value_type =
                Type::For(property_cell_value_map, broker());
            representation = MachineRepresentation::kTaggedPointer;

            // We can only use the property cell value map for map check
            // elimination if it's stable, i.e. the HeapObject wasn't
            // mutated without the cell state being updated.
            if (property_cell_value_map.is_stable()) {
              dependencies()->DependOnStableMap(property_cell_value_map);
              map = property_cell_value_map;
            }
          }
        }
        value = effect = graph()->NewNode(
            simplified()->LoadField(ForPropertyCellValue(
                representation, property_cell_value_type, map, name)),
            jsgraph()->ConstantNoHole(property_cell, broker()), effect,
            control);
      }
    }
  } else if (access_mode == AccessMode::kStore) {
    DCHECK_EQ(receiver, lookup_start_object);
    DCHECK(!property_details.IsReadOnly());
    switch (property_details.cell_type()) {
      case PropertyCellType::kConstant: {
        // Record a code dependency on the cell, and just deoptimize if the new
        // value doesn't match the previous value stored inside the cell.
        dependencies()->DependOnGlobalProperty(property_cell);
        Node* check = graph()->NewNode(
            simplified()->ReferenceEqual(), value,
            jsgraph()->ConstantNoHole(property_cell_value, broker()));
        effect = graph()->NewNode(
            simplified()->CheckIf(DeoptimizeReason::kValueMismatch), check,
            effect, control);
        break;
      }
      case PropertyCellType::kConstantType: {
        // Record a code dependency on the cell, and just deoptimize if the new
        // value's type doesn't match the type of the previous value in the
        // cell.
        dependencies()->DependOnGlobalProperty(property_cell);
        Type property_cell_value_type;
        MachineRepresentation representation = MachineRepresentation::kTagged;
        if (property_cell_value.IsHeapObject()) {
          MapRef property_cell_value_map =
              property_cell_value.AsHeapObject().map(broker());
          dependencies()->DependOnStableMap(property_cell_value_map);

          // Check that the {value} is a HeapObject.
          value = effect = graph()->NewNode(simplified()->CheckHeapObject(),
                                            value, effect, control);
          // Check {value} map against the {property_cell_value} map.
          effect = graph()->NewNode(
              simplified()->CheckMaps(CheckMapsFlag::kNone,
                                      ZoneRefSet<Map>(property_cell_value_map)),
              value, effect, control);
          property_cell_value_type = Type::OtherInternal();
          representation = MachineRepresentation::kTaggedPointer;
        } else {
          // Check that the {value} is a Smi.
          value = effect = graph()->NewNode(
              simplified()->CheckSmi(FeedbackSource()), value, effect, control);
          property_cell_value_type = Type::SignedSmall();
          representation = MachineRepresentation::kTaggedSigned;
        }
        effect =
            graph()->NewNode(simplified()->StoreField(ForPropertyCellValue(
                                 representation, property_cell_value_type,
                                 OptionalMapRef(), name)),
                             jsgraph()->ConstantNoHole(property_cell, broker()),
                             value, effect, control);
        break;
      }
      case PropertyCellType::kMutable: {
        // Record a code dependency on the cell, and just deoptimize if the
        // property ever becomes read-only.
        dependencies()->DependOnGlobalProperty(property_cell);
        effect =
            graph()->NewNode(simplified()->StoreField(ForPropertyCellValue(
                                 MachineRepresentation::kTagged,
                                 Type::NonInternal(), OptionalMapRef(), name)),
                             jsgraph()->ConstantNoHole(property_cell, broker()),
                             value, effect, control);
        break;
      }
      case PropertyCellType::kUndefined:
      case PropertyCellType::kInTransition:
        UNREACHABLE();
    }
  } else {
    return NoChange();
  }

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSNativeContextSpecialization::ReduceJSLoadGlobal(Node* node) {
  JSLoadGlobalNode n(node);
  LoadGlobalParameters const& p = n.Parameters();
  if (!p.feedback().IsValid()) return NoChange();

  ProcessedFeedback const& processed =
      broker()->GetFeedbackForGlobalAccess(FeedbackSource(p.feedback()));
  if (processed.IsInsufficient()) return NoChange();

  GlobalAccessFeedback const& feedback = processed.AsGlobalAccess();
  if (feedback.IsScriptContextSlot()) {
    Effect effect = n.effect();
    Control control = n.control();
    Node* script_context =
        jsgraph()->ConstantNoHole(feedback.script_context(), broker());
    Node* value;
    if (feedback.immutable()) {
      value = effect = graph()->NewNode(
          javascript()->LoadContext(0, feedback.slot_index(), true),
          script_context, effect);
    } else {
      value = effect = graph()->NewNode(
          javascript()->LoadScriptContext(0, feedback.slot_index()),
          script_context, effect, control);
    }
    ReplaceWithValue(node, value, effect, control);
    return Replace(value);
  } else if (feedback.IsPropertyCell()) {
    return ReduceGlobalAccess(node, nullptr, nullptr, nullptr, p.name(),
                              AccessMode::kLoad, nullptr,
                              feedback.property_cell());
  } else {
    DCHECK(feedback.IsMegamorphic());
    return NoChange();
  }
}

Reduction JSNativeContextSpecialization::ReduceJSStoreGlobal(Node* node) {
  JSStoreGlobalNode n(node);
  StoreGlobalParameters const& p = n.Parameters();
  Node* value = n.value();
  if (!p.feedback().IsValid()) return NoChange();

  ProcessedFeedback const& processed =
      broker()->GetFeedbackForGlobalAccess(FeedbackSource(p.feedback()));
  if (processed.IsInsufficient()) return NoChange();

  GlobalAccessFeedback const& feedback = processed.AsGlobalAccess();
  if (feedback.IsScriptContextSlot()) {
    if (feedback.immutable()) return NoChange();
    Node* effect = n.effect();
    Node* control = n.control();
    Node* script_context =
        jsgraph()->ConstantNoHole(feedback.script_context(), broker());
    effect = control = graph()->NewNode(
        javascript()->StoreScriptContext(0, feedback.slot_index()), value,
        script_context, effect, control);
    ReplaceWithValue(node, value, effect, control);
    return Replace(value);
  } else if (feedback.IsPropertyCell()) {
    return ReduceGlobalAccess(node, nullptr, nullptr, value, p.name(),
                              AccessMode::kStore, nullptr,
                              feedback.property_cell());
  } else {
    DCHECK(feedback.IsMegamorphic());
    return NoChange();
  }
}

Reduction JSNativeContextSpecialization::ReduceMegaDOMPropertyAccess(
    Node* node, Node* value, MegaDOMPropertyAccessFeedback const& feedback,
    FeedbackSource const& source) {
  DCHECK(node->opcode() == IrOpcode::kJSLoadNamed ||
         node->opcode() == IrOpcode::kJSLoadProperty);
  // TODO(mslekova): Add support and tests for kJSLoadNamedFromSuper.
  static_assert(JSLoadNamedNode::ObjectIndex() == 0 &&
                    JSLoadPropertyNode::ObjectIndex() == 0,
                "Assumptions about ObjectIndex have changed, please update "
                "this function.");

  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* frame_state = NodeProperties::GetFrameStateInput(node);

  Node* lookup_start_object = NodeProperties::GetValueInput(node, 0);

  if (!dependencies()->DependOnMegaDOMProtector()) {
    return NoChange();
  }

  FunctionTemplateInfoRef function_template_info = feedback.info();
  int16_t range_start =
      function_template_info.allowed_receiver_instance_type_range_start();
  int16_t range_end =
      function_template_info.allowed_receiver_instance_type_range_end();
  DCHECK_IMPLIES(range_start == 0, range_end == 0);
  DCHECK_LE(range_start, range_end);

  // TODO(mslekova): This could be a new InstanceTypeCheck operator
  // that gets lowered later on (e.g. during generic lowering).
  Node* receiver_map = effect =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()),
                       lookup_start_object, effect, control);
  Node* receiver_instance_type = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapInstanceType()),
      receiver_map, effect, control);

  if (v8_flags.experimental_embedder_instance_types && range_start != 0) {
    // Embedder instance ID is set, doing a simple range check.
    Node* diff_to_start =
        graph()->NewNode(simplified()->NumberSubtract(), receiver_instance_type,
                         jsgraph()->ConstantNoHole(range_start));
    Node* range_length = jsgraph()->ConstantNoHole(range_end - range_start);

    // TODO(mslekova): Once we have the InstanceTypeCheck operator, we could
    // lower it to Uint32LessThan later on to perform what is done in bounds.h.
    Node* check = graph()->NewNode(simplified()->NumberLessThanOrEqual(),
                                   diff_to_start, range_length);
    effect = graph()->NewNode(
        simplified()->CheckIf(DeoptimizeReason::kWrongInstanceType), check,
        effect, control);
  } else if (function_template_info.is_signature_undefined(broker())) {
    // Signature is undefined, enough to check if the receiver is a JSApiObject.
    Node* check =
        graph()->NewNode(simplified()->NumberEqual(), receiver_instance_type,
                         jsgraph()->ConstantNoHole(JS_API_OBJECT_TYPE));
    effect = graph()->NewNode(
        simplified()->CheckIf(DeoptimizeReason::kWrongInstanceType), check,
        effect, control);
  } else {
    // Calling out to builtin to do signature check.
    Callable callable = Builtins::CallableFor(
        isolate(), Builtin::kCallFunctionTemplate_CheckCompatibleReceiver);
    int stack_arg_count = callable.descriptor().GetStackParameterCount() +
                          1 /* implicit receiver */;

    CallDescriptor* call_descriptor = Linkage::GetStubCallDescriptor(
        graph()->zone(), callable.descriptor(), stack_arg_count,
        CallDescriptor::kNeedsFrameState, Operator::kNoProperties);

    Node* inputs[8] = {
        jsgraph()->HeapConstantNoHole(callable.code()),
        jsgraph()->ConstantNoHole(function_template_info, broker()),
        jsgraph()->Int32Constant(stack_arg_count),
        lookup_start_object,
        jsgraph()->ConstantNoHole(native_context(), broker()),
        frame_state,
        effect,
        control};

    value = effect = control =
        graph()->NewNode(common()->Call(call_descriptor), 8, inputs);
    return Replace(value);
  }

  value = InlineApiCall(lookup_start_object, lookup_start_object, frame_state,
                        nullptr /*value*/, &effect, &control,
                        function_template_info);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSNativeContextSpecialization::ReduceNamedAccess(
    Node* node, Node* value, NamedAccessFeedback const& feedback,
    AccessMode access_mode, Node* key) {
  DCHECK(node->opcode() == IrOpcode::kJSLoadNamed ||
         node->opcode() == IrOpcode::kJSSetNamedProperty ||
         node->opcode() == IrOpcode::kJSLoadProperty ||
         node->opcode() == IrOpcode::kJSSetKeyedProperty ||
         node->opcode() == IrOpcode::kJSDefineNamedOwnProperty ||
         node->opcode() == IrOpcode::kJSDefineKeyedOwnPropertyInLiteral ||
         node->opcode() == IrOpcode::kJSHasProperty ||
         node->opcode() == IrOpcode::kJSLoadNamedFromSuper ||
         node->opcode() == IrOpcode::kJSDefineKeyedOwnProperty);
  static_assert(JSLoadNamedNode::ObjectIndex() == 0 &&
                JSSetNamedPropertyNode::ObjectIndex() == 0 &&
                JSLoadPropertyNode::ObjectIndex() == 0 &&
                JSSetKeyedPropertyNode::ObjectIndex() == 0 &&
                JSDefineNamedOwnPropertyNode::ObjectIndex() == 0 &&
                JSSetNamedPropertyNode::ObjectIndex() == 0 &&
                JSDefineKeyedOwnPropertyInLiteralNode::ObjectIndex() == 0 &&
                JSHasPropertyNode::ObjectIndex() == 0 &&
                JSDefineKeyedOwnPropertyNode::ObjectIndex() == 0);
  static_assert(JSLoadNamedFromSuperNode::ReceiverIndex() == 0);

  Node* context = NodeProperties::GetContextInput(node);
  FrameState frame_state{NodeProperties::GetFrameStateInput(node)};
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  // receiver = the object we pass to the accessor (if any) as the "this" value.
  Node* receiver = NodeProperties::GetValueInput(node, 0);
  // lookup_start_object = the object where we start looking for the property.
  Node* lookup_start_object;
  if (node->opcode() == IrOpcode::kJSLoadNamedFromSuper) {
    DCHECK(v8_flags.super_ic);
    JSLoadNamedFromSuperNode n(node);
    // Lookup start object is the __proto__ of the home object.
    lookup_start_object = effect =
        BuildLoadPrototypeFromObject(n.home_object(), effect, control);
  } else {
    lookup_start_object = receiver;
  }

  // Either infer maps from the graph or use the feedback.
  ZoneVector<MapRef> inferred_maps(zone());
  if (!InferMaps(lookup_start_object, effect, &inferred_maps)) {
    for (MapRef map : feedback.maps()) {
      inferred_maps.push_back(map);
    }
  }
  RemoveImpossibleMaps(lookup_start_object, &inferred_maps);

  // Check if we have an access o.x or o.x=v where o is the target native
  // contexts' global proxy, and turn that into a direct access to the
  // corresponding global object instead.
  if (inferred_maps.size() == 1) {
    MapRef lookup_start_object_map = inferred_maps[0];
    if (lookup_start_object_map.equals(
            native_context().global_proxy_object(broker()).map(broker()))) {
      if (!native_context().GlobalIsDetached(broker())) {
        OptionalPropertyCellRef cell =
            native_context().global_object(broker()).GetPropertyCell(
                broker(), feedback.name());
        if (!cell.has_value()) return NoChange();
        // Note: The map check generated by ReduceGlobalAccesses ensures that we
        // will deopt when/if GlobalIsDetached becomes true.
        return ReduceGlobalAccess(node, lookup_start_object, receiver, value,
                                  feedback.name(), access_mode, key, *cell
"""


```