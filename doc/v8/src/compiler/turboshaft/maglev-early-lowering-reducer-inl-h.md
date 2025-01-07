Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for the functionalities of a specific V8 header file (`maglev-early-lowering-reducer-inl.h`). It also has several conditional requests based on the file extension and relationship to JavaScript.

2. **Initial Analysis of the File:**
   - **Filename:** `maglev-early-lowering-reducer-inl.h` strongly suggests this is an inline header file related to the "Maglev" compiler pipeline in V8 and focuses on "early lowering" optimizations. The `.inl.h` suffix signifies inline implementations.
   - **Copyright and Headers:** The copyright notice and included headers like `<optional>`, `"src/compiler/feedback-source.h"`, `"src/compiler/globals.h"`, `"src/compiler/turboshaft/assembler.h"`, etc., confirm it's a core part of the V8 compiler. The `turboshaft` directory indicates the newer Turboshaft pipeline.
   - **Namespace:** `v8::internal::compiler::turboshaft` further reinforces its location within the compiler.
   - **Template Class:** The core of the file is a template class `MaglevEarlyLoweringReducer`. The `template <class Next>` suggests this class is part of a chain of reducers or a similar pattern, where `Next` is the next stage in the process.
   - **Comment Block:** The comment within the class definition is crucial. It states the primary function: to provide "helpers" for lowering Maglev operators during the `MaglevGraphBuildingPhase`. It also hints at a possible future shift towards using Simplified or JS operators instead.
   - **Macros:** The `#include "src/compiler/turboshaft/define-assembler-macros.inc"` and `#include "src/compiler/turboshaft/undef-assembler-macros.inc"` indicate the use of assembler macros, likely for generating low-level code.
   - **`TURBOSHAFT_REDUCER_BOILERPLATE`:**  This macro suggests this class is indeed a "reducer" within the Turboshaft framework, responsible for transforming the intermediate representation of the code.

3. **Functionality Breakdown (Iterating through methods):**  I go through each public method of the `MaglevEarlyLoweringReducer` class and try to deduce its purpose based on its name, parameters, and internal logic:

   - **`CheckInstanceType`:**  Checks if an object's instance type falls within a specified range. It handles both single type checks and range checks. The `DeoptimizeIf` calls indicate that type mismatches lead to deoptimization.
   - **`CheckedInternalizedString`:** Verifies that an object is an internalized string (a string that has been added to V8's string interning table for optimization). It handles thin strings and deoptimizes if the object is not an internalized string.
   - **`CheckValueEqualsString`:** Checks if an object is equal to a specific internalized string. It handles potential non-string types and uses `StringEqual` for the comparison.
   - **`CheckConstructResult`:**  Implements the logic for handling the return value of a constructor call, potentially discarding the returned object and using the implicit receiver instead, according to ECMA specifications.
   - **`LoadScriptContextSideData` and `LoadScriptContextPropertyFromSideData`:** These deal with accessing properties stored in the script context's side data, which is a way to store context-specific information.
   - **`LoadHeapNumberFromScriptContext`:**  Specifically loads a HeapNumber (V8's representation of numbers) from the script context.
   - **`StoreScriptContextSlowPath`:** Handles the slower path for storing values into the script context, including checks for constness and type safety (especially for HeapNumbers).
   - **`CheckDerivedConstructResult`:**  Enforces the requirement that derived constructor calls must return an object.
   - **`UpdateJSArrayLength`:** Efficiently updates the length property of a JavaScript array.
   - **`TransitionElementsKindOrCheckMap` and `TransitionMultipleElementsKind`:** These methods are related to changing the internal representation (elements kind) of a JavaScript array for optimization. They involve map transitions.
   - **`TransitionElementsKind` (private):** The core logic for transitioning the elements kind.
   - **`JSAnyIsNotPrimitive`:**  Checks if a HeapObject is not a primitive value.
   - **`HasInPrototypeChain`:** Implements the `in` operator's prototype chain lookup logic.
   - **`MigrateMapIfNeeded`:** Checks if an object's map is deprecated and attempts to migrate the object to a newer map.
   - **`ExtendPropertiesBackingStore`:**  Expands the internal storage for object properties.
   - **`GeneratorStore`:**  Handles saving the state of a JavaScript generator object.

4. **Answering Specific Questions:**

   - **Functionality List:**  Based on the method analysis, I create a bulleted list summarizing the core functionalities.
   - **.tq Extension:** I check the filename. Since it ends in `.h`, not `.tq`, it's not a Torque source file.
   - **JavaScript Relationship:** I identify methods that directly relate to JavaScript concepts like instance types, strings, constructors, arrays, prototypes, and generators. I then choose a relevant method (`CheckInstanceType`) and provide a JavaScript example to illustrate its purpose.
   - **Code Logic Reasoning:** I select a method with clear logic (`UpdateJSArrayLength`) and provide a hypothetical input and output scenario.
   - **Common Programming Errors:** I consider the types of checks being performed (instance types, string equality, constructor results) and relate them to common JavaScript errors, such as assuming an object is of a specific type or not handling constructor return values correctly.

5. **Refinement and Organization:** I review the generated answer for clarity, accuracy, and completeness. I ensure the formatting is readable and the examples are easy to understand. I group related functionalities together. I also double-check that I've addressed all parts of the initial request.

This systematic approach allows me to dissect the C++ code, understand its purpose within the V8 compiler, and connect it back to user-level JavaScript concepts. The comments in the code are invaluable for this process.

这个C++头文件 `v8/src/compiler/turboshaft/maglev-early-lowering-reducer-inl.h` 定义了一个名为 `MaglevEarlyLoweringReducer` 的类，它在 V8 的 Turboshaft 编译管道的早期降低阶段（early lowering phase）中扮演着重要的角色。 该类的主要功能是提供一些辅助方法（helpers），用于将一些 Maglev 操作符转换为更低级的表示形式。

**主要功能概览:**

* **类型检查和断言:**  提供了一系列方法来检查对象的类型，并在类型不符合预期时触发反优化（deoptimization）。
* **字符串处理:** 包含了检查对象是否为内部化字符串，以及比较对象与内部化字符串是否相等的功能。
* **构造函数结果处理:**  实现了处理构造函数调用结果的逻辑，包括根据 ECMA 规范决定是否使用构造函数返回的对象或隐式接收者。
* **上下文（Context）操作:** 提供了加载和存储脚本上下文侧边数据（side data）的功能，用于访问上下文中的变量。
* **数组长度更新:**  包含更新 JavaScript 数组长度的逻辑。
* **元素类型转换 (Elements Kind Transition):**  支持在满足特定条件时，改变 JavaScript 对象的元素类型，以进行性能优化。
* **原型链检查:**  实现了检查对象是否在原型链中拥有特定原型的功能。
* **Map 迁移:**  提供了在需要时迁移对象 Map 的功能，这通常与对象形状（shape）的优化有关。
* **属性存储扩展:**  包含扩展对象属性存储后备数组（backing store）的功能。
* **生成器状态存储:**  提供了存储 JavaScript 生成器对象状态的功能。

**关于文件扩展名和 Torque:**

`v8/src/compiler/turboshaft/maglev-early-lowering-reducer-inl.h` 以 `.h` 结尾，而不是 `.tq`。 因此，它不是一个 V8 Torque 源代码文件。 Torque 文件通常用于定义 V8 内部的类型和内置函数。 `.h` 文件是 C++ 头文件，用于声明类、函数和其他实体。  `inl.h` 后缀通常表示该头文件包含了内联函数的定义。

**与 JavaScript 功能的关系及示例:**

`MaglevEarlyLoweringReducer` 中的许多功能都直接与 JavaScript 的运行时行为和语义相关。以下是一些例子：

1. **类型检查 (`CheckInstanceType`):**  JavaScript 是动态类型语言，因此在运行时进行类型检查非常重要。V8 需要确保对象具有预期的类型才能进行某些优化。

   ```javascript
   function processObject(obj) {
     if (typeof obj === 'string') {
       console.log("It's a string: " + obj);
     } else if (typeof obj === 'number') {
       console.log("It's a number: " + obj);
     } else if (obj instanceof Array) {
       console.log("It's an array with length: " + obj.length);
     } else {
       console.log("It's some other object");
     }
   }

   processObject("hello"); // V8 内部可能使用类似 CheckInstanceType 来判断 obj 是否为字符串
   processObject(123);    // V8 内部可能使用类似 CheckInstanceType 来判断 obj 是否为数字
   processObject([1, 2]); // V8 内部可能使用类似 CheckInstanceType 来判断 obj 是否为数组
   processObject({});     // V8 内部可能使用类似 CheckInstanceType 来判断 obj 是否为普通对象
   ```

2. **构造函数结果处理 (`CheckConstructResult` 和 `CheckDerivedConstructResult`):** JavaScript 中构造函数的返回值有特定的规则。如果构造函数返回一个对象，则该对象将作为 `new` 表达式的结果，否则将使用 `this` 对象（对于非派生构造函数）或抛出错误（对于派生构造函数）。

   ```javascript
   function MyClass() {
     this.value = 10;
     return { custom: true }; // 返回一个对象
   }

   const obj1 = new MyClass();
   console.log(obj1.value); // undefined，因为构造函数返回了新的对象
   console.log(obj1.custom); // true

   class DerivedClass extends Array {
     constructor() {
       super();
       return 123; // 尝试返回一个非对象
     }
   }

   try {
     const obj2 = new DerivedClass(); // 会抛出 TypeError，因为派生构造函数必须返回对象或 undefined
   } catch (e) {
     console.error(e);
   }
   ```

3. **原型链检查 (`HasInPrototypeChain`):**  `in` 运算符用于检查对象或其原型链上是否存在某个属性。

   ```javascript
   const proto = { z: 3 };
   const obj = { x: 1, __proto__: proto };

   console.log('x' in obj);   // true
   console.log('z' in obj);   // true (继承自原型)
   console.log('y' in obj);   // false
   ```

4. **数组长度更新 (`UpdateJSArrayLength`):** 当向数组添加元素时，其 `length` 属性需要更新。

   ```javascript
   const arr = [1, 2, 3];
   console.log(arr.length); // 3
   arr[5] = 6;
   console.log(arr.length); // 6
   console.log(arr);       // [ 1, 2, 3, <2 empty items>, 6 ]
   ```

**代码逻辑推理示例:**

让我们以 `UpdateJSArrayLength` 方法为例进行逻辑推理。

**假设输入:**

* `length_raw`:  表示数组当前长度的原始 Word32 值，假设为 `3`。
* `object`:  一个 JavaScript 数组对象。
* `index`:   要设置的元素的索引，假设为 `5`。

**代码逻辑:**

```c++
  V<Smi> UpdateJSArrayLength(V<Word32> length_raw, V<JSArray> object,
                             V<Word32> index) {
    Label<Smi> done(this);
    IF (__ Uint32LessThan(index, length_raw)) {
      GOTO(done, __ TagSmi(length_raw));
    } ELSE {
      V<Word32> new_length_raw =
          __ Word32Add(index, 1);  // This cannot overflow.
      V<Smi> new_length_tagged = __ TagSmi(new_length_raw);
      __ Store(object, new_length_tagged, StoreOp::Kind::TaggedBase(),
               MemoryRepresentation::TaggedSigned(),
               WriteBarrierKind::kNoWriteBarrier, JSArray::kLengthOffset);
      GOTO(done, new_length_tagged);
    }

    BIND(done, length_tagged);
    return length_tagged;
  }
```

**推理:**

1. **比较索引和当前长度:** 代码首先比较 `index` (5) 和 `length_raw` (3)。 由于 5 不小于 3，条件 `__ Uint32LessThan(index, length_raw)` 为假。
2. **计算新长度:** 进入 `ELSE` 分支。 `new_length_raw` 被计算为 `index + 1`，即 `5 + 1 = 6`。
3. **标记新长度:** `new_length_tagged` 将原始长度值 6 转换为 Smi（Small Integer）。
4. **存储新长度:**  使用 `__ Store` 指令将新的标记长度 `new_length_tagged` 存储回 `object` 数组的长度字段 (`JSArray::kLengthOffset`)。
5. **跳转到 done 标签:**  执行 `GOTO(done, new_length_tagged)`，将新的标记长度作为结果传递给 `done` 标签。

**预期输出:**

该方法将返回一个 Smi，其值为 6，表示数组的新长度。数组对象的内部长度属性也将被更新为 6。

**用户常见的编程错误示例:**

1. **类型假设错误:**  用户经常会假设变量的类型，而没有进行适当的检查。例如，假设一个函数参数始终是字符串，然后直接调用字符串的方法，而没有检查它是否真的是字符串。

   ```javascript
   function processString(str) {
     console.log(str.toUpperCase()); // 如果 str 不是字符串，会抛出错误
   }

   processString("hello");
   processString(123); // TypeError: str.toUpperCase is not a function
   ```
   `MaglevEarlyLoweringReducer` 中的 `CheckInstanceType` 等方法旨在在编译时或运行时尽早捕获这类错误，并进行反优化，以便执行更安全的代码路径。

2. **构造函数返回值理解错误:**  初学者可能不理解 JavaScript 构造函数的返回值规则，导致意外的结果。他们可能认为无论构造函数返回什么，都会得到 `this` 对象。

   ```javascript
   function MyClass() {
     this.value = 10;
     return null; // 预期返回对象，但返回了 null
   }

   const obj = new MyClass();
   console.log(obj.value); // 预期输出 10，但实际上 obj 是 null，访问属性会报错
   ```
   `CheckConstructResult` 和 `CheckDerivedConstructResult` 帮助 V8 正确处理这些情况，并确保符合语言规范。

3. **原型链理解错误:**  用户可能不清楚属性查找在原型链上的工作方式，导致访问到 `undefined` 或意外的值。

   ```javascript
   const proto = { greeting: "Hello" };
   const obj = { name: "World" };
   Object.setPrototypeOf(obj, proto);

   console.log(obj.greeting); // "Hello" (从原型链上找到)
   console.log(obj.age);      // undefined (原型链上不存在)
   ```
   `HasInPrototypeChain` 方法体现了 V8 如何在内部处理原型链的查找。

总而言之，`v8/src/compiler/turboshaft/maglev-early-lowering-reducer-inl.h` 中定义的 `MaglevEarlyLoweringReducer` 类是 V8 编译器优化管道中的一个关键组件，它通过提供各种辅助方法，实现了对 JavaScript 代码的早期分析、类型检查和低级转换，从而为后续的优化和代码生成奠定了基础。 这些功能与 JavaScript 的核心概念和运行时行为紧密相关，并在内部帮助 V8 提高性能和保证代码的正确性。

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/maglev-early-lowering-reducer-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/maglev-early-lowering-reducer-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_MAGLEV_EARLY_LOWERING_REDUCER_INL_H_
#define V8_COMPILER_TURBOSHAFT_MAGLEV_EARLY_LOWERING_REDUCER_INL_H_

#include <optional>

#include "src/compiler/feedback-source.h"
#include "src/compiler/globals.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/index.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/deoptimizer/deoptimize-reason.h"
#include "src/objects/contexts.h"
#include "src/objects/instance-type-inl.h"

namespace v8::internal::compiler::turboshaft {

#include "src/compiler/turboshaft/define-assembler-macros.inc"

template <class Next>
class MaglevEarlyLoweringReducer : public Next {
  // This Reducer provides some helpers that are used during
  // MaglevGraphBuildingPhase to lower some Maglev operators. Depending on what
  // we decide going forward (regarding SimplifiedLowering for instance), we
  // could introduce new Simplified or JS operations instead of using these
  // helpers to lower, and turn the helpers into regular REDUCE methods in the
  // new simplified lowering or in MachineLoweringReducer.

 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(MaglevEarlyLowering)

  void CheckInstanceType(V<Object> input, V<FrameState> frame_state,
                         const FeedbackSource& feedback,
                         InstanceType first_instance_type,
                         InstanceType last_instance_type, bool check_smi) {
    if (check_smi) {
      __ DeoptimizeIf(__ IsSmi(input), frame_state,
                      DeoptimizeReason::kWrongInstanceType, feedback);
    }

    V<i::Map> map = __ LoadMapField(input);

    if (first_instance_type == last_instance_type) {
#if V8_STATIC_ROOTS_BOOL
      if (InstanceTypeChecker::UniqueMapOfInstanceType(first_instance_type)) {
        std::optional<RootIndex> expected_index =
            InstanceTypeChecker::UniqueMapOfInstanceType(first_instance_type);
        CHECK(expected_index.has_value());
        Handle<HeapObject> expected_map =
            Cast<HeapObject>(isolate_->root_handle(expected_index.value()));
        __ DeoptimizeIfNot(__ TaggedEqual(map, __ HeapConstant(expected_map)),
                           frame_state, DeoptimizeReason::kWrongInstanceType,
                           feedback);
        return;
      }
#endif  // V8_STATIC_ROOTS_BOOL
      V<Word32> instance_type = __ LoadInstanceTypeField(map);
      __ DeoptimizeIfNot(__ Word32Equal(instance_type, first_instance_type),
                         frame_state, DeoptimizeReason::kWrongInstanceType,
                         feedback);
    } else {
      __ DeoptimizeIfNot(CheckInstanceTypeIsInRange(map, first_instance_type,
                                                    last_instance_type),
                         frame_state, DeoptimizeReason::kWrongInstanceType,
                         feedback);
    }
  }

  V<InternalizedString> CheckedInternalizedString(
      V<Object> object, OpIndex frame_state, bool check_smi,
      const FeedbackSource& feedback) {
    if (check_smi) {
      __ DeoptimizeIf(__ IsSmi(object), frame_state, DeoptimizeReason::kSmi,
                      feedback);
    }

    Label<InternalizedString> done(this);
    V<Map> map = __ LoadMapField(object);
    V<Word32> instance_type = __ LoadInstanceTypeField(map);

    // Go to the slow path if this is a non-string, or a non-internalised
    // string.
    static_assert((kStringTag | kInternalizedTag) == 0);
    IF (UNLIKELY(__ Word32BitwiseAnd(
            instance_type, kIsNotStringMask | kIsNotInternalizedMask))) {
      // Deopt if this isn't a string.
      __ DeoptimizeIf(__ Word32BitwiseAnd(instance_type, kIsNotStringMask),
                      frame_state, DeoptimizeReason::kWrongMap, feedback);
      // Deopt if this isn't a thin string.
      static_assert(base::bits::CountPopulation(kThinStringTagBit) == 1);
      __ DeoptimizeIfNot(__ Word32BitwiseAnd(instance_type, kThinStringTagBit),
                         frame_state, DeoptimizeReason::kWrongMap, feedback);
      // Load internalized string from thin string.
      V<InternalizedString> intern_string =
          __ template LoadField<InternalizedString>(
              object, AccessBuilder::ForThinStringActual());
      GOTO(done, intern_string);
    } ELSE {
      GOTO(done, V<InternalizedString>::Cast(object));
    }

    BIND(done, result);
    return result;
  }

  void CheckValueEqualsString(V<Object> object, InternalizedStringRef value,
                              V<FrameState> frame_state,
                              const FeedbackSource& feedback) {
    IF_NOT (LIKELY(__ TaggedEqual(object, __ HeapConstant(value.object())))) {
      __ DeoptimizeIfNot(__ ObjectIsString(object), frame_state,
                         DeoptimizeReason::kNotAString, feedback);
      V<Boolean> is_same_string_bool =
          __ StringEqual(V<String>::Cast(object),
                         __ template HeapConstant<String>(value.object()));
      __ DeoptimizeIf(
          __ RootEqual(is_same_string_bool, RootIndex::kFalseValue, isolate_),
          frame_state, DeoptimizeReason::kWrongValue, feedback);
    }
  }

  V<Object> CheckConstructResult(V<Object> construct_result,
                                 V<Object> implicit_receiver) {
    // If the result is an object (in the ECMA sense), we should get rid
    // of the receiver and use the result; see ECMA-262 version 5.1
    // section 13.2.2-7 on page 74.
    Label<Object> done(this);

    GOTO_IF(
        __ RootEqual(construct_result, RootIndex::kUndefinedValue, isolate_),
        done, implicit_receiver);

    // If the result is a smi, it is *not* an object in the ECMA sense.
    GOTO_IF(__ IsSmi(construct_result), done, implicit_receiver);

    // Check if the type of the result is not an object in the ECMA sense.
    GOTO_IF(JSAnyIsNotPrimitive(V<HeapObject>::Cast(construct_result)), done,
            construct_result);

    // Throw away the result of the constructor invocation and use the
    // implicit receiver as the result.
    GOTO(done, implicit_receiver);

    BIND(done, result);
    return result;
  }

  V<Object> LoadScriptContextSideData(V<Context> script_context, int index) {
    V<FixedArray> side_table = __ template LoadTaggedField<FixedArray>(
        script_context,
        Context::OffsetOfElementAt(Context::CONTEXT_SIDE_TABLE_PROPERTY_INDEX));
    return __ LoadTaggedField(side_table,
                              FixedArray::OffsetOfElementAt(
                                  index - Context::MIN_CONTEXT_EXTENDED_SLOTS));
  }

  V<Object> LoadScriptContextPropertyFromSideData(V<Object> side_data) {
    ScopedVar<Object> property(this, side_data);
    IF_NOT (__ IsSmi(side_data)) {
      property = __ LoadTaggedField(
          side_data, ContextSidePropertyCell::kPropertyDetailsRawOffset);
    }
    return property;
  }

  V<Object> LoadHeapNumberFromScriptContext(V<Context> script_context,
                                            int index,
                                            V<HeapNumber> heap_number) {
    V<Object> data = __ LoadScriptContextSideData(script_context, index);
    V<Object> property = __ LoadScriptContextPropertyFromSideData(data);
    ScopedVar<HeapNumber> result(this, heap_number);
    IF (__ TaggedEqual(
            property,
            __ SmiConstant(ContextSidePropertyCell::MutableHeapNumber()))) {
      result = __ AllocateHeapNumberWithValue(
          __ LoadHeapNumberValue(heap_number), isolate_->factory());
    }
    return result;
  }

  void StoreScriptContextSlowPath(V<Context> script_context,
                                  V<Object> old_value, V<Object> new_value,
                                  V<Object> side_data,
                                  V<FrameState> frame_state,
                                  const FeedbackSource& feedback,
                                  Label<>& done) {
    // Check if Undefined.
    __ DeoptimizeIf(
        __ RootEqual(side_data, RootIndex::kUndefinedValue, isolate_),
        frame_state, DeoptimizeReason::kWrongValue, feedback);
    V<Object> property = __ LoadScriptContextPropertyFromSideData(side_data);
    // Check for const case.
    __ DeoptimizeIf(
        __ TaggedEqual(property,
                       __ SmiConstant(ContextSidePropertyCell::Const())),
        frame_state, DeoptimizeReason::kWrongValue, feedback);
    if (v8_flags.script_context_mutable_heap_number) {
      // Check for smi case
      IF (__ TaggedEqual(
              property, __ SmiConstant(ContextSidePropertyCell::SmiMarker()))) {
        __ DeoptimizeIfNot(__ IsSmi(new_value), frame_state,
                           DeoptimizeReason::kWrongValue, feedback);
      } ELSE {
        // Check mutable heap number case.
        ScopedVar<Float64> number_value(this);
        IF (__ IsSmi(new_value)) {
          number_value =
              __ ChangeInt32ToFloat64(__ UntagSmi(V<Smi>::Cast(new_value)));
        } ELSE {
          V<i::Map> map = __ LoadMapField(new_value);
          __ DeoptimizeIfNot(
              __ TaggedEqual(map, __ HeapConstant(factory_->heap_number_map())),
              frame_state, DeoptimizeReason::kWrongValue, feedback);
          number_value = __ LoadHeapNumberValue(V<HeapNumber>::Cast(new_value));
        }
        __ StoreField(old_value, AccessBuilder::ForHeapNumberValue(),
                      number_value);
        GOTO(done);
      }
    }
  }

  void CheckDerivedConstructResult(V<Object> construct_result,
                                   V<FrameState> frame_state,
                                   V<NativeContext> native_context,
                                   LazyDeoptOnThrow lazy_deopt_on_throw) {
    // The result of a derived construct should be an object (in the ECMA
    // sense).
    Label<> do_throw(this);

    // If the result is a smi, it is *not* an object in the ECMA sense.
    GOTO_IF(__ IsSmi(construct_result), do_throw);

    // Check if the type of the result is not an object done the ECMA sense.
    IF_NOT (JSAnyIsNotPrimitive(V<HeapObject>::Cast(construct_result))) {
      GOTO(do_throw);
      BIND(do_throw);
      __ CallRuntime_ThrowConstructorReturnedNonObject(
          isolate_, frame_state, native_context, lazy_deopt_on_throw);
      // ThrowConstructorReturnedNonObject should not return.
      __ Unreachable();
    }
  }

  V<Smi> UpdateJSArrayLength(V<Word32> length_raw, V<JSArray> object,
                             V<Word32> index) {
    Label<Smi> done(this);
    IF (__ Uint32LessThan(index, length_raw)) {
      GOTO(done, __ TagSmi(length_raw));
    } ELSE {
      V<Word32> new_length_raw =
          __ Word32Add(index, 1);  // This cannot overflow.
      V<Smi> new_length_tagged = __ TagSmi(new_length_raw);
      __ Store(object, new_length_tagged, StoreOp::Kind::TaggedBase(),
               MemoryRepresentation::TaggedSigned(),
               WriteBarrierKind::kNoWriteBarrier, JSArray::kLengthOffset);
      GOTO(done, new_length_tagged);
    }

    BIND(done, length_tagged);
    return length_tagged;
  }

  void TransitionElementsKindOrCheckMap(
      V<Object> object, V<Map> map, V<FrameState> frame_state,
      const ZoneVector<compiler::MapRef>& transition_sources,
      const MapRef transition_target, const FeedbackSource& feedback) {
    Label<Map> end(this);

    TransitionElementsKind(object, map, transition_sources, transition_target,
                           end);

    __ DeoptimizeIfNot(
        __ TaggedEqual(map, __ HeapConstant(transition_target.object())),
        frame_state, DeoptimizeReason::kWrongMap, feedback);
    GOTO(end, map);
    BIND(end, result);
    USE(result);
  }

  V<Map> TransitionMultipleElementsKind(
      V<Object> object, V<Map> map,
      const ZoneVector<compiler::MapRef>& transition_sources,
      const MapRef transition_target) {
    Label<Map> end(this);

    TransitionElementsKind(object, map, transition_sources, transition_target,
                           end);
    GOTO(end, map);
    BIND(end, result);
    return result;
  }

  void TransitionElementsKind(
      V<Object> object, V<Map> map,
      const ZoneVector<compiler::MapRef>& transition_sources,
      const MapRef transition_target, Label<Map>& end) {
    // Turboshaft's TransitionElementsKind operation loads the map everytime, so
    // we don't call it to have a single map load (in practice,
    // LateLoadElimination should probably eliminate the subsequent map loads,
    // but let's not risk it).
    V<Map> target_map = __ HeapConstant(transition_target.object());

    for (const compiler::MapRef transition_source : transition_sources) {
      bool is_simple = IsSimpleMapChangeTransition(
          transition_source.elements_kind(), transition_target.elements_kind());
      IF (__ TaggedEqual(map, __ HeapConstant(transition_source.object()))) {
        if (is_simple) {
          __ StoreField(object, AccessBuilder::ForMap(), target_map);
        } else {
          __ CallRuntime_TransitionElementsKind(
              isolate_, __ NoContextConstant(), V<HeapObject>::Cast(object),
              target_map);
        }
        GOTO(end, target_map);
      }
    }
  }

  V<Word32> JSAnyIsNotPrimitive(V<HeapObject> heap_object) {
    V<Map> map = __ LoadMapField(heap_object);
    if (V8_STATIC_ROOTS_BOOL) {
      // All primitive object's maps are allocated at the start of the read only
      // heap. Thus JS_RECEIVER's must have maps with larger (compressed)
      // addresses.
      return __ Uint32LessThanOrEqual(
          InstanceTypeChecker::kNonJsReceiverMapLimit,
          __ TruncateWordPtrToWord32(__ BitcastTaggedToWordPtr(map)));
    } else {
      static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
      return __ Uint32LessThanOrEqual(FIRST_JS_RECEIVER_TYPE,
                                      __ LoadInstanceTypeField(map));
    }
  }

  V<Boolean> HasInPrototypeChain(V<Object> object, HeapObjectRef prototype,
                                 V<FrameState> frame_state,
                                 V<NativeContext> native_context,
                                 LazyDeoptOnThrow lazy_deopt_on_throw) {
    Label<Boolean> done(this);

    V<Boolean> true_bool = __ HeapConstant(factory_->true_value());
    V<Boolean> false_bool = __ HeapConstant(factory_->false_value());
    V<HeapObject> target_proto = __ HeapConstant(prototype.object());

    GOTO_IF(__ IsSmi(object), done, false_bool);

    LoopLabel<Map> loop(this);
    GOTO(loop, __ LoadMapField(object));

    BIND_LOOP(loop, map) {
      Label<> object_is_direct(this);

      IF (UNLIKELY(CheckInstanceTypeIsInRange(map, FIRST_TYPE,
                                              LAST_SPECIAL_RECEIVER_TYPE))) {
        Label<> call_runtime(this);
        V<Word32> instance_type = __ LoadInstanceTypeField(map);

        GOTO_IF(__ Word32Equal(instance_type, JS_PROXY_TYPE), call_runtime);

        V<Word32> bitfield =
            __ template LoadField<Word32>(map, AccessBuilder::ForMapBitField());
        int mask = Map::Bits1::HasNamedInterceptorBit::kMask |
                   Map::Bits1::IsAccessCheckNeededBit::kMask;
        GOTO_IF_NOT(__ Word32BitwiseAnd(bitfield, mask), object_is_direct);
        GOTO(call_runtime);

        BIND(call_runtime);
        GOTO(done, __ CallRuntime_HasInPrototypeChain(
                       isolate_, frame_state, native_context,
                       lazy_deopt_on_throw, object, target_proto));
      }
      GOTO(object_is_direct);

      BIND(object_is_direct);
      V<HeapObject> proto = __ template LoadField<HeapObject>(
          map, AccessBuilder::ForMapPrototype());
      GOTO_IF(__ RootEqual(proto, RootIndex::kNullValue, isolate_), done,
              false_bool);
      GOTO_IF(__ TaggedEqual(proto, target_proto), done, true_bool);

      GOTO(loop, __ LoadMapField(proto));
    }

    BIND(done, result);
    return result;
  }

  V<Map> MigrateMapIfNeeded(V<HeapObject> object, V<Map> map,
                            V<FrameState> frame_state,
                            const FeedbackSource& feedback) {
    ScopedVar<Map> result(this, map);

    V<Word32> bitfield3 =
        __ template LoadField<Word32>(map, AccessBuilder::ForMapBitField3());
    IF (UNLIKELY(__ Word32BitwiseAnd(bitfield3,
                                     Map::Bits3::IsDeprecatedBit::kMask))) {
      V<Object> result = __ CallRuntime_TryMigrateInstance(
          isolate_, __ NoContextConstant(), object);
      __ DeoptimizeIf(__ ObjectIsSmi(result), frame_state,
                      DeoptimizeReason::kInstanceMigrationFailed, feedback);
      // Reload the map since TryMigrateInstance might have changed it.
      result = __ LoadMapField(V<HeapObject>::Cast(result));
    }

    return result;
  }

  V<PropertyArray> ExtendPropertiesBackingStore(
      V<PropertyArray> old_property_array, V<JSObject> object, int old_length,
      V<FrameState> frame_state, const FeedbackSource& feedback) {
    // Allocate new PropertyArray.
    int new_length = old_length + JSObject::kFieldsAdded;
    Uninitialized<PropertyArray> new_property_array =
        __ template Allocate<PropertyArray>(
            __ IntPtrConstant(PropertyArray::SizeFor(new_length)),
            AllocationType::kYoung);
    __ InitializeField(new_property_array, AccessBuilder::ForMap(),
                       __ HeapConstant(factory_->property_array_map()));

    // Copy existing properties over.
    for (int i = 0; i < old_length; i++) {
      V<Object> old_value = __ template LoadField<Object>(
          old_property_array, AccessBuilder::ForPropertyArraySlot(i));
      __ InitializeField(new_property_array,
                         AccessBuilder::ForPropertyArraySlot(i), old_value);
    }

    // Initialize new properties to undefined.
    V<Undefined> undefined = __ HeapConstant(factory_->undefined_value());
    for (int i = 0; i < JSObject::kFieldsAdded; ++i) {
      __ InitializeField(new_property_array,
                         AccessBuilder::ForPropertyArraySlot(old_length + i),
                         undefined);
    }

    // Read the hash.
    ScopedVar<Word32> hash(this);
    if (old_length == 0) {
      // The object might still have a hash, stored in properties_or_hash. If
      // properties_or_hash is a SMI, then it's the hash. It can also be an
      // empty PropertyArray.
      V<Object> hash_obj = __ template LoadField<Object>(
          object, AccessBuilder::ForJSObjectPropertiesOrHash());
      IF (__ IsSmi(hash_obj)) {
        hash = __ Word32ShiftLeft(__ UntagSmi(V<Smi>::Cast(hash_obj)),
                                  PropertyArray::HashField::kShift);
      } ELSE {
        hash = __ Word32Constant(PropertyArray::kNoHashSentinel);
      }
    } else {
      V<Smi> hash_smi = __ template LoadField<Smi>(
          old_property_array, AccessBuilder::ForPropertyArrayLengthAndHash());
      hash = __ Word32BitwiseAnd(__ UntagSmi(hash_smi),
                                 PropertyArray::HashField::kMask);
    }

    // Add the new length and write the length-and-hash field.
    static_assert(PropertyArray::LengthField::kShift == 0);
    V<Word32> length_and_hash = __ Word32BitwiseOr(hash, new_length);
    __ InitializeField(new_property_array,
                       AccessBuilder::ForPropertyArrayLengthAndHash(),
                       __ TagSmi(length_and_hash));

    V<PropertyArray> initialized_new_property_array =
        __ FinishInitialization(std::move(new_property_array));

    // Replace the old property array in {object}.
    __ StoreField(object, AccessBuilder::ForJSObjectPropertiesOrHash(),
                  initialized_new_property_array);

    return initialized_new_property_array;
  }

  void GeneratorStore(V<Context> context, V<JSGeneratorObject> generator,
                      base::SmallVector<OpIndex, 32> parameters_and_registers,
                      int suspend_id, int bytecode_offset) {
    V<FixedArray> array = __ template LoadTaggedField<FixedArray>(
        generator, JSGeneratorObject::kParametersAndRegistersOffset);
    for (int i = 0; static_cast<size_t>(i) < parameters_and_registers.size();
         i++) {
      __ Store(array, parameters_and_registers[i], StoreOp::Kind::TaggedBase(),
               MemoryRepresentation::AnyTagged(),
               WriteBarrierKind::kFullWriteBarrier,
               FixedArray::OffsetOfElementAt(i));
    }
    __ Store(generator, __ SmiConstant(Smi::FromInt(suspend_id)),
             StoreOp::Kind::TaggedBase(), MemoryRepresentation::TaggedSigned(),
             WriteBarrierKind::kNoWriteBarrier,
             JSGeneratorObject::kContinuationOffset);
    __ Store(generator, __ SmiConstant(Smi::FromInt(bytecode_offset)),
             StoreOp::Kind::TaggedBase(), MemoryRepresentation::TaggedSigned(),
             WriteBarrierKind::kNoWriteBarrier,
             JSGeneratorObject::kInputOrDebugPosOffset);

    __ Store(generator, context, StoreOp::Kind::TaggedBase(),
             MemoryRepresentation::AnyTagged(),
             WriteBarrierKind::kFullWriteBarrier,
             JSGeneratorObject::kContextOffset);
  }

 private:
  V<Word32> CheckInstanceTypeIsInRange(V<Map> map,
                                       InstanceType first_instance_type,
                                       InstanceType last_instance_type) {
    V<Word32> instance_type = __ LoadInstanceTypeField(map);

    if (first_instance_type == 0) {
      return __ Uint32LessThanOrEqual(instance_type, last_instance_type);
    } else {
      return __ Uint32LessThanOrEqual(
          __ Word32Sub(instance_type, first_instance_type),
          last_instance_type - first_instance_type);
    }
  }

  Isolate* isolate_ = __ data() -> isolate();
  LocalIsolate* local_isolate_ = isolate_->AsLocalIsolate();
  JSHeapBroker* broker_ = __ data() -> broker();
  LocalFactory* factory_ = local_isolate_->factory();
};

#include "src/compiler/turboshaft/undef-assembler-macros.inc"

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_MAGLEV_EARLY_LOWERING_REDUCER_INL_H_

"""

```