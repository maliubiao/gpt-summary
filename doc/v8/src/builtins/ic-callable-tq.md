Response: Let's break down the thought process for analyzing this Torque code.

1. **Understand the Goal:** The core request is to summarize the functionality of the `ic-callable.tq` file, relate it to JavaScript, provide logical reasoning with examples, and highlight common programming errors.

2. **Initial Scan and Keywords:**  Start by skimming the code for recurring keywords and patterns. I see `FeedbackVector`, `slotId`, `Monomorphic`, `Megamorphic`, `Initialize`, `Transition`, `Call`, `Construct`, `Prototype`, `Context`, `AllocationSite`. These immediately suggest a focus on optimizing function calls and object construction. The `ic` namespace hints at "inline caching," a common optimization technique.

3. **Core Concepts Identification:**  From the keywords, I can identify the main concepts:
    * **Feedback Vector:**  This likely stores information about past calls to optimize future calls.
    * **Monomorphic/Megamorphic:** These are states of optimization. Monomorphic means a function has been called with the same type of arguments/receiver consistently. Megamorphic means there's too much variation.
    * **Call/Construct:**  The code explicitly handles both function calls and object construction.
    * **Context:** JavaScript execution contexts are important for security and isolation.
    * **Allocation Site:**  Relevant for optimizing object creation.

4. **Macro Analysis (Iterative Approach):**  Now, let's examine each macro individually.

    * **`IncrementCallCount`:**  Simple - tracks how many times a function associated with a feedback slot has been called.

    * **`kCallFeedbackContentFieldMask` / `kCallFeedbackContentFieldShift`:** These likely deal with encoding extra information within the call count. The names suggest bit manipulation.

    * **`IsMonomorphic`:**  Checks if the feedback slot contains a weak reference to a specific target. Weak references are used so that the optimization data doesn't prevent garbage collection.

    * **`InSameNativeContext`:**  Verifies if two contexts belong to the same JavaScript realm. This is important for security.

    * **`TryInitializeAsMonomorphic`:** This is crucial. It attempts to store a weak reference to the *target function* in the feedback vector, marking it as monomorphic *if* the target is a regular function in the *same context*. The unwrapping of bound functions is also important. The label `TransitionToMegamorphic` indicates what happens if the conditions aren't met.

    * **`TransitionToMegamorphic`:** Marks the feedback slot as megamorphic, meaning no specific optimization can be applied.

    * **`TaggedEqualPrototypeApplyFunction`:** Checks if a target is `Function.prototype.apply`. This is a special case in JavaScript due to its flexibility.

    * **`FeedbackValueIsReceiver`:**  Checks a bit in the call count to see if the feedback slot is currently tracking the *receiver* of the call (the `this` value).

    * **`SetCallFeedbackContent`:** Modifies the call count to indicate whether the feedback is about the target or the receiver. This confirms the bit manipulation theory.

    * **`CollectCallFeedback`:** This is the heart of the call optimization. It checks the current feedback state (monomorphic, megamorphic, uninitialized). It tries to stay monomorphic if possible, handles the `apply` case, and transitions to megamorphic if necessary. The "TryReinitializeAsMonomorphic" and the logic around feedback cells indicate more advanced optimization strategies.

    * **`CollectInstanceOfFeedback`:** Similar to `CollectCallFeedback` but specifically for `instanceof` checks. It seems simpler, potentially because `instanceof` is less dynamic than regular function calls.

    * **`BothTaggedEqualArrayFunction`:**  Checks if two values are the same and equal to the `Array` constructor. This is specific to array construction optimization.

    * **`CreateAllocationSiteInFeedbackVector`:**  Creates a special object to track how `Array` objects are allocated.

    * **`CastFeedbackVector`:** Handles cases where feedback might be optional or not needed, based on the `updateFeedbackMode`.

    * **`CollectConstructFeedback`:**  Optimizes object construction (`new`). It has special handling for `Array` construction using `AllocationSite`s.

5. **JavaScript Relationship and Examples:**  Now that I understand the mechanics, I can connect it to JavaScript behavior. Monomorphic calls are like calling the same function on objects of the same "shape" repeatedly. Megamorphic calls happen when the types change frequently. The `apply` case is directly related to the `Function.prototype.apply` method. `instanceof` is a core JavaScript operator. The `new Array()` case is a specific constructor scenario.

6. **Logical Reasoning and Examples:**  For each macro, I can think about the "if this, then that" logic. For `TryInitializeAsMonomorphic`, if the target is a function in the same context, store it; otherwise, transition. For `CollectCallFeedback`, the sequence of checks (monomorphic, megamorphic, uninitialized) is a clear logical flow. I can invent simple JavaScript snippets to illustrate these scenarios.

7. **Common Programming Errors:**  Consider what could go wrong that would defeat these optimizations. Calling the same function with wildly different argument types, using `apply` with arbitrary receivers, and dynamically changing object prototypes are all good examples.

8. **Structure and Refine:**  Finally, organize the information logically. Start with a high-level summary, then go into detail for each macro. Use clear headings and bullet points. Ensure the JavaScript examples are concise and relevant. Review and refine the language for clarity and accuracy. For example, initially I might just say "optimizes calls," but refining it to "dynamically optimizes function calls and object construction based on observed behavior" is more precise.

This iterative process of scanning, identifying concepts, analyzing macros, connecting to JavaScript, reasoning logically, and refining helps to produce a comprehensive understanding of the Torque code.
这个v8 Torque 源代码文件 `v8/src/builtins/ic-callable.tq` 的主要功能是**实现了V8引擎中用于优化可调用对象（函数和构造函数）调用的内联缓存（Inline Caching, IC）机制的关键组成部分**。它定义了一系列 Torque 宏，用于收集和更新关于函数调用和对象构造的反馈信息，并根据这些信息来优化后续的调用。

**与 Javascript 的关系和示例:**

内联缓存是 V8 引擎为了提高 JavaScript 代码执行效率而采用的一种重要的优化技术。当一个函数或构造函数被调用时，V8 会记录下一些信息，比如被调用函数的类型、接收者（`this`）的类型等。当下次再次调用相同的函数时，V8 会首先检查这些记录的信息（存储在 `FeedbackVector` 中），如果情况与之前相同，V8 就可以直接使用之前生成的优化代码，而无需重新进行类型检查和代码生成，从而加速执行。

**`ic-callable.tq` 中的宏主要负责以下与 JavaScript 相关的优化：**

1. **跟踪函数调用的“形状” (Shape Tracking for Function Calls):**
   - `TryInitializeAsMonomorphic`:  当一个函数第一次被调用时，尝试将其标记为单态 (monomorphic)，意味着该函数目前只被一种类型的接收者调用。
   - `IsMonomorphic`: 检查一个函数是否是单态的。
   - `TransitionToMegamorphic`: 当一个函数被多种不同类型的接收者调用时，将其标记为多态 (megamorphic)，这时 V8 就无法进行过于激进的优化。
   - `CollectCallFeedback`:  在函数调用时收集反馈信息，判断是否能保持单态，或者需要转换为多态。

   **JavaScript 示例:**

   ```javascript
   function greet(person) {
     return "Hello, " + person.name;
   }

   const john = { name: "John" };
   const jane = { name: "Jane" };

   greet(john); // 第一次调用，可能会将 greet 标记为单态 (接收者是拥有 name 属性的对象)
   greet(jane); // 第二次调用，接收者类型相同，仍然是单态，可以利用之前的优化
   ```

2. **优化 `Function.prototype.apply` 的调用:**
   - `TaggedEqualPrototypeApplyFunction`:  检查被调用的目标是否是 `Function.prototype.apply`。
   - `FeedbackValueIsReceiver`: 检查反馈向量中记录的是目标函数还是接收者。
   - `CollectCallFeedback` 中有专门处理 `apply` 的逻辑，因为它允许动态改变 `this` 值，需要特殊处理以进行优化。

   **JavaScript 示例:**

   ```javascript
   function sayHi() {
     console.log("Hi, " + this.name);
   }

   const person1 = { name: "Alice" };
   const person2 = { name: "Bob" };

   sayHi.apply(person1); // this 指向 person1
   sayHi.apply(person2); // this 指向 person2， V8 会尝试优化这种调用模式
   ```

3. **优化构造函数调用 (`new`)：**
   - `CollectConstructFeedback`:  在构造函数调用时收集反馈，用于优化对象创建过程。
   - `BothTaggedEqualArrayFunction`: 检查目标和 `new.target` 是否都是 `Array` 构造函数，用于优化数组的创建。
   - `CreateAllocationSiteInFeedbackVector`:  为 `Array` 构造函数创建分配站点 (AllocationSite)，用于更精细地跟踪数组对象的创建情况，以便进行诸如逃逸分析等优化。

   **JavaScript 示例:**

   ```javascript
   class Point {
     constructor(x, y) {
       this.x = x;
       this.y = y;
     }
   }

   new Point(1, 2); // V8 会记录 Point 的构造信息
   new Point(3, 4); // 后续的 Point 构造可能会利用之前记录的信息进行优化

   new Array(10); // 特殊处理，优化数组创建
   ```

4. **优化 `instanceof` 操作符:**
   - `CollectInstanceOfFeedback`: 收集关于 `instanceof` 操作的反馈信息，以优化类型检查。

   **JavaScript 示例:**

   ```javascript
   class Animal {}
   class Dog extends Animal {}

   const myDog = new Dog();

   myDog instanceof Dog;     // V8 会记录这种 instanceof 检查
   myDog instanceof Animal;  // 可能会有单独的记录和优化
   ```

**代码逻辑推理与假设输入输出:**

以 `TryInitializeAsMonomorphic` 宏为例：

**假设输入：**

* `context`: 当前执行上下文。
* `maybeTarget`:  一个 `JSAny` 类型的可能的目标函数对象，例如一个 `JSFunction` 实例。
* `feedbackVector`: 用于存储反馈信息的 `FeedbackVector` 对象。
* `slotId`:  `FeedbackVector` 中用于存储此调用点反馈信息的槽位 ID。

**代码逻辑：**

1. 尝试将 `maybeTarget` 转换为 `HeapObject`。如果转换失败（例如 `maybeTarget` 是原始值），则跳转到 `TransitionToMegamorphic`。
2. 如果 `maybeTarget` 是 `JSBoundFunction`，则解包获取其绑定的原始目标函数。
3. 尝试将解包后的目标函数转换为 `JSFunction`。如果转换失败，则跳转到 `TransitionToMegamorphic`。
4. 检查目标函数的上下文是否与当前的 `context` 相同。如果不同，则跳转到 `TransitionToMegamorphic`（跨上下文调用通常难以进行单态优化）。
5. 如果所有条件都满足，则在 `feedbackVector` 的指定 `slotId` 中存储一个指向 `maybeTarget` 的弱引用，并将此槽位标记为已初始化并为单态。

**可能的输出和副作用：**

* **成功 (未跳转):**  `feedbackVector` 的指定槽位被更新为指向 `maybeTarget` 的弱引用，并且记录了 'Call:Initialize' 的反馈更新。
* **跳转到 `TransitionToMegamorphic`:**  `feedbackVector` 未被修改，流程跳转到标记为多态的逻辑。

**假设输入和输出示例：**

```javascript
// 假设在 V8 内部执行以下操作
const feedbackVector = ...; // 获取一个 FeedbackVector
const slotId = 5;
const globalContext = ...; // 获取全局上下文

function myFunction() { return 1; }
const boundFunction = myFunction.bind(null);

// 首次调用 myFunction
ic.callable.TryInitializeAsMonomorphic(globalContext, myFunction, feedbackVector, slotId);
// 输出：feedbackVector 的 slotId 槽位现在可能包含一个指向 myFunction 的弱引用

// 首次调用 boundFunction
ic.callable.TryInitializeAsMonomorphic(globalContext, boundFunction, feedbackVector, slotId + 1);
// 输出：feedbackVector 的 slotId + 1 槽位现在可能包含一个指向 myFunction (解绑后) 的弱引用

// 跨上下文调用
const otherContextMyFunction = ...; // 来自另一个上下文的同名函数
ic.callable.TryInitializeAsMonomorphic(globalContext, otherContextMyFunction, feedbackVector, slotId + 2);
// 输出：跳转到 TransitionToMegamorphic，因为上下文不同
```

**涉及用户常见的编程错误:**

这些底层的优化机制通常对用户是透明的，但一些常见的编程模式可能会影响 V8 的优化效果，导致性能下降。

1. **频繁改变对象的类型或形状 (Changing object structure frequently):**

   ```javascript
   function Point(x, y) {
     this.x = x;
     this.y = y;
   }

   const p1 = new Point(1, 2);
   p1.z = 3; // 动态添加属性会改变对象的形状，影响优化

   function operate(obj) {
     return obj.x + obj.y;
   }

   operate(p1); // 第一次调用，可能会假设 obj 有 x 和 y 属性
   const p2 = new Point(4, 5);
   operate(p2); // 第二次调用，obj 仍然有 x 和 y，优化可能继续
   ```

2. **在 `apply` 或 `call` 中使用多种不同的接收者类型 (Using `apply` with diverse receiver types):**

   ```javascript
   function logName() {
     console.log(this.name);
   }

   const person = { name: "Alice" };
   const company = { name: "Acme Corp" };

   logName.apply(person);
   logName.apply(company); // 接收者类型不同，可能导致从单态变为多态
   ```

3. **过度使用动态特性，导致类型信息难以预测 (Overusing dynamic features):**

   ```javascript
   function process(item) {
     if (typeof item.process === 'function') {
       item.process();
     } else {
       console.log("Cannot process this item");
     }
   }

   const obj1 = { process: () => console.log("Processing obj1") };
   const obj2 = {};

   process(obj1);
   process(obj2); // `item.process` 的存在与否不确定，影响优化
   ```

4. **在构造函数中动态添加属性 (Dynamically adding properties in constructors after initial object creation):**

   ```javascript
   class DynamicPoint {
     constructor(x) {
       this.x = x;
       if (Math.random() > 0.5) {
         this.y = 0; // 有时添加 y 属性，有时不添加
       }
     }
   }

   new DynamicPoint(1);
   new DynamicPoint(2); // 创建的对象形状可能不同，影响构造函数的优化
   ```

总结来说，`ic-callable.tq` 文件是 V8 引擎内联缓存机制的核心，它通过 Torque 宏定义了收集、分析和利用函数调用和对象构造反馈信息的逻辑，从而实现 JavaScript 代码的动态优化。理解其功能有助于开发者编写更易于 V8 优化的代码，避免常见的性能陷阱。

### 提示词
```
这是目录为v8/src/builtins/ic-callable.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

namespace ic {
namespace callable {

extern macro IncrementCallCount(FeedbackVector, uintptr): void;
const kCallFeedbackContentFieldMask: constexpr int32
    generates 'FeedbackNexus::CallFeedbackContentField::kMask';
const kCallFeedbackContentFieldShift: constexpr uint32
    generates 'FeedbackNexus::CallFeedbackContentField::kShift';

macro IsMonomorphic(feedback: MaybeObject, target: JSAny): bool {
  return IsWeakReferenceToObject(feedback, target);
}

macro InSameNativeContext(lhs: Context, rhs: Context): bool {
  return LoadNativeContext(lhs) == LoadNativeContext(rhs);
}

macro TryInitializeAsMonomorphic(
    implicit context: Context)(maybeTarget: JSAny,
    feedbackVector: FeedbackVector,
    slotId: uintptr): void labels TransitionToMegamorphic {
  const targetHeapObject =
      Cast<HeapObject>(maybeTarget) otherwise TransitionToMegamorphic;

  let unwrappedTarget = targetHeapObject;
  while (Is<JSBoundFunction>(unwrappedTarget)) {
    unwrappedTarget =
        UnsafeCast<JSBoundFunction>(unwrappedTarget).bound_target_function;
  }

  const unwrappedTargetJSFunction =
      Cast<JSFunction>(unwrappedTarget) otherwise TransitionToMegamorphic;
  if (!InSameNativeContext(unwrappedTargetJSFunction.context, context)) {
    goto TransitionToMegamorphic;
  }

  StoreWeakReferenceInFeedbackVector(feedbackVector, slotId, targetHeapObject);
  ReportFeedbackUpdate(feedbackVector, slotId, 'Call:Initialize');
}

macro TransitionToMegamorphic(
    implicit context: Context)(feedbackVector: FeedbackVector,
    slotId: uintptr): void {
  StoreFeedbackVectorSlot(feedbackVector, slotId, kMegamorphicSymbol);
  ReportFeedbackUpdate(feedbackVector, slotId, 'Call:TransitionMegamorphic');
}

macro TaggedEqualPrototypeApplyFunction(
    implicit context: Context)(target: JSAny): bool {
  return TaggedEqual(target, GetPrototypeApplyFunction());
}

macro FeedbackValueIsReceiver(
    implicit context: Context)(feedbackVector: FeedbackVector,
    slotId: uintptr): bool {
  const callCount: intptr = SmiUntag(Cast<Smi>(LoadFeedbackVectorSlot(
      feedbackVector, slotId, kTaggedSize)) otherwise return false);
  return (callCount & IntPtrConstant(kCallFeedbackContentFieldMask)) !=
      IntPtrConstant(0);
}

macro SetCallFeedbackContent(
    implicit context: Context)(feedbackVector: FeedbackVector, slotId: uintptr,
    callFeedbackContent: constexpr CallFeedbackContent): void {
  // Load the call count field from the feecback vector.
  const callCount: intptr = SmiUntag(Cast<Smi>(LoadFeedbackVectorSlot(
      feedbackVector, slotId, kTaggedSize)) otherwise return);
  // The second lowest bits of the call count are used to state whether the
  // feedback collected is a target or a receiver. Change that bit based on the
  // callFeedbackContent input.
  const callFeedbackContentFieldMask: intptr =
      ~IntPtrConstant(kCallFeedbackContentFieldMask);
  const newCount: intptr = (callCount & callFeedbackContentFieldMask) |
      Convert<intptr>(Signed(
          %RawConstexprCast<constexpr uint32>(callFeedbackContent)
          << kCallFeedbackContentFieldShift));
  StoreFeedbackVectorSlot(
      feedbackVector, slotId, SmiTag(newCount), SKIP_WRITE_BARRIER,
      kTaggedSize);
  ReportFeedbackUpdate(feedbackVector, slotId, 'Call:SetCallFeedbackContent');
}

macro CollectCallFeedback(
    maybeTarget: JSAny, maybeReceiver: Lazy<JSAny>, context: Context,
    maybeFeedbackVector: Undefined|FeedbackVector, slotId: uintptr): void {
  // TODO(v8:9891): Remove this dcheck once all callers are ported to Torque.
  // This dcheck ensures correctness of maybeFeedbackVector's type which can
  // be easily broken for calls from CSA.
  dcheck(
      IsUndefined(maybeFeedbackVector) ||
      Is<FeedbackVector>(maybeFeedbackVector));
  const feedbackVector =
      Cast<FeedbackVector>(maybeFeedbackVector) otherwise return;
  IncrementCallCount(feedbackVector, slotId);

  try {
    const feedback: MaybeObject =
        LoadFeedbackVectorSlot(feedbackVector, slotId);
    if (IsMonomorphic(feedback, maybeTarget)) return;
    if (IsMegamorphic(feedback)) return;
    if (IsUninitialized(feedback)) goto TryInitializeAsMonomorphic;

    // If cleared, we have a new chance to become monomorphic.
    const feedbackValue: HeapObject =
        MaybeObjectToStrong(feedback) otherwise TryReinitializeAsMonomorphic;

    if (FeedbackValueIsReceiver(feedbackVector, slotId) &&
        TaggedEqualPrototypeApplyFunction(maybeTarget)) {
      // If the Receiver is recorded and the target is
      // Function.prototype.apply, check whether we can stay monomorphic based
      // on the receiver.
      if (IsMonomorphic(feedback, RunLazy(maybeReceiver))) {
        return;
      } else {
        // If not, reinitialize the feedback with target.
        SetCallFeedbackContent(
            feedbackVector, slotId, CallFeedbackContent::kTarget);
        TryInitializeAsMonomorphic(maybeTarget, feedbackVector, slotId)
            otherwise TransitionToMegamorphic;
        return;
      }
    }

    // Try transitioning to a feedback cell.
    // Check if {target}s feedback cell matches the {feedbackValue}.
    const target =
        Cast<JSFunction>(maybeTarget) otherwise TransitionToMegamorphic;
    const targetFeedbackCell: FeedbackCell = target.feedback_cell;
    if (TaggedEqual(feedbackValue, targetFeedbackCell)) return;

    // Check if {target} and {feedbackValue} are both JSFunctions with
    // the same feedback vector cell, and that those functions were
    // actually compiled already.
    const feedbackValueJSFunction =
        Cast<JSFunction>(feedbackValue) otherwise TransitionToMegamorphic;
    const feedbackCell: FeedbackCell = feedbackValueJSFunction.feedback_cell;
    if (!TaggedEqual(feedbackCell, targetFeedbackCell))
      goto TransitionToMegamorphic;

    StoreWeakReferenceInFeedbackVector(feedbackVector, slotId, feedbackCell);
    ReportFeedbackUpdate(feedbackVector, slotId, 'Call:FeedbackVectorCell');
  } label TryReinitializeAsMonomorphic {
    SetCallFeedbackContent(
        feedbackVector, slotId, CallFeedbackContent::kTarget);
    goto TryInitializeAsMonomorphic;
  } label TryInitializeAsMonomorphic {
    let recordedFunction = maybeTarget;
    if (TaggedEqualPrototypeApplyFunction(maybeTarget)) {
      recordedFunction = RunLazy(maybeReceiver);
      SetCallFeedbackContent(
          feedbackVector, slotId, CallFeedbackContent::kReceiver);
    } else {
      dcheck(!FeedbackValueIsReceiver(feedbackVector, slotId));
    }
    TryInitializeAsMonomorphic(recordedFunction, feedbackVector, slotId)
        otherwise TransitionToMegamorphic;
  } label TransitionToMegamorphic {
    TransitionToMegamorphic(feedbackVector, slotId);
  }
}

macro CollectInstanceOfFeedback(
    maybeTarget: JSAny, context: Context,
    maybeFeedbackVector: Undefined|FeedbackVector, slotId: uintptr): void {
  // TODO(v8:9891): Remove this dcheck once all callers are ported to Torque.
  // This dcheck ensures correctness of maybeFeedbackVector's type which can
  // be easily broken for calls from CSA.
  dcheck(
      IsUndefined(maybeFeedbackVector) ||
      Is<FeedbackVector>(maybeFeedbackVector));
  const feedbackVector =
      Cast<FeedbackVector>(maybeFeedbackVector) otherwise return;
  // Note: The call count is not incremented.

  try {
    const feedback: MaybeObject =
        LoadFeedbackVectorSlot(feedbackVector, slotId);
    if (IsMonomorphic(feedback, maybeTarget)) return;
    if (IsMegamorphic(feedback)) return;
    if (IsUninitialized(feedback)) goto TryInitializeAsMonomorphic;

    // If cleared, we have a new chance to become monomorphic.
    const _feedbackValue: HeapObject =
        MaybeObjectToStrong(feedback) otherwise TryInitializeAsMonomorphic;

    goto TransitionToMegamorphic;
  } label TryInitializeAsMonomorphic {
    TryInitializeAsMonomorphic(maybeTarget, feedbackVector, slotId)
        otherwise TransitionToMegamorphic;
  } label TransitionToMegamorphic {
    TransitionToMegamorphic(feedbackVector, slotId);
  }
}

macro BothTaggedEqualArrayFunction(
    implicit context: Context)(first: JSAny, second: JSAny): bool {
  return TaggedEqual(first, second) && TaggedEqual(second, GetArrayFunction());
}

extern macro CreateAllocationSiteInFeedbackVector(FeedbackVector, uintptr):
    AllocationSite;

macro CastFeedbackVector(
    maybeFeedbackVector: Undefined|FeedbackVector,
    updateFeedbackMode: constexpr UpdateFeedbackMode):
    FeedbackVector labels Fallback {
  if constexpr (updateFeedbackMode == UpdateFeedbackMode::kGuaranteedFeedback) {
    return UnsafeCast<FeedbackVector>(maybeFeedbackVector);
  } else if constexpr (
      updateFeedbackMode == UpdateFeedbackMode::kOptionalFeedback) {
    return Cast<FeedbackVector>(maybeFeedbackVector) otherwise goto Fallback;
  } else if constexpr (updateFeedbackMode == UpdateFeedbackMode::kNoFeedback) {
    goto Fallback;
  } else {
    unreachable;
  }
}

macro CollectConstructFeedback(
    implicit context: Context)(target: JSAny, newTarget: JSAny,
    maybeFeedbackVector: Undefined|FeedbackVector, slotId: TaggedIndex,
    updateFeedbackMode: constexpr UpdateFeedbackMode):
    never labels ConstructGeneric,
    ConstructArray(AllocationSite) {
  // TODO(v8:9891): Remove this dcheck once all callers are ported to Torque.
  // This dcheck ensures correctness of maybeFeedbackVector's type which can
  // be easily broken for calls from CSA.
  dcheck(
      IsUndefined(maybeFeedbackVector) ||
      Is<FeedbackVector>(maybeFeedbackVector));

  const feedbackVector = CastFeedbackVector(
      maybeFeedbackVector, updateFeedbackMode) otherwise goto ConstructGeneric;
  // TODO(42200059): Propagate TaggedIndex usage.
  const slotIdUintptr = Unsigned(TaggedIndexToIntPtr(slotId));
  IncrementCallCount(feedbackVector, slotIdUintptr);

  try {
    const feedback: MaybeObject =
        LoadFeedbackVectorSlot(feedbackVector, slotIdUintptr);
    if (IsMonomorphic(feedback, newTarget)) goto ConstructGeneric;
    if (IsMegamorphic(feedback)) goto ConstructGeneric;
    if (IsUninitialized(feedback)) goto TryInitializeAsMonomorphic;

    if (!IsWeakOrCleared(feedback)) {
      const feedbackAsStrong = %RawDownCast<Object>(feedback);
      if (Is<AllocationSite>(feedbackAsStrong)) {
        if (BothTaggedEqualArrayFunction(target, newTarget)) {
          goto ConstructArray(UnsafeCast<AllocationSite>(feedbackAsStrong));
        }
        goto TransitionToMegamorphic;
      }
    }

    // If cleared, we have a new chance to become monomorphic.
    const _feedbackValue: HeapObject =
        MaybeObjectToStrong(feedback) otherwise TryInitializeAsMonomorphic;

    goto TransitionToMegamorphic;
  } label TryInitializeAsMonomorphic {
    if (BothTaggedEqualArrayFunction(target, newTarget)) {
      // In this case we can skip unwrapping and context validation since we
      // know the target is the current context's array function.
      const allocationSite =
          CreateAllocationSiteInFeedbackVector(feedbackVector, slotIdUintptr);
      ReportFeedbackUpdate(
          feedbackVector, slotIdUintptr, 'Construct:CreateAllocationSite');
      goto ConstructArray(allocationSite);
    }

    TryInitializeAsMonomorphic(newTarget, feedbackVector, slotIdUintptr)
        otherwise TransitionToMegamorphic;
  } label TransitionToMegamorphic {
    TransitionToMegamorphic(feedbackVector, slotIdUintptr);
  }
  goto ConstructGeneric;
}

}  // namespace callable
}  // namespace ic
```