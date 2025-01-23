Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/feedback-vector.cc`. The request also includes specific conditions related to file extensions, JavaScript relevance, logic inference, common programming errors, and that this is the second part of a two-part request.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The code manipulates `FeedbackNexus` objects. These objects are associated with inline caches (ICs) and store feedback about operations like property access, function calls, and binary/comparison operations. The feedback is used to optimize future executions of the same code.

2. **Break Down Functionality by Method:**  Go through each method in the provided snippet and determine its role:

    * `GetInlineCacheState()`: Determines the current state of the IC (uninitialized, monomorphic, polymorphic, etc.) based on the feedback stored.
    * `ConfigurePropertyCellMode()`: Configures the IC for global property access using a `PropertyCell`.
    * `ConfigureLexicalVarMode()`: Configures the IC for lexical variable access, storing context and slot information.
    * `ConfigureHandlerMode()`: Configures the IC with a handler, typically for megamorphic cases.
    * `ConfigureCloneObject()`: Manages feedback for object cloning, tracking the maps of objects being cloned.
    * `GetCallCount()`: Retrieves the call count for call ICs.
    * `SetSpeculationMode()`/`GetSpeculationMode()`:  Handles speculation hints for call ICs.
    * `GetCallFeedbackContent()`: Retrieves additional content related to call feedback.
    * `ComputeCallFrequency()`: Calculates the frequency of function calls.
    * `ConfigureMonomorphic()`: Configures the IC for the case where only one receiver map has been encountered.
    * `ConfigurePolymorphic()`: Configures the IC for multiple receiver maps.
    * `ExtractMaps()`: Retrieves the cached maps from the feedback.
    * `ExtractMegaDOMHandler()`: Retrieves a specific handler for megamorphic DOM access.
    * `ExtractMapsAndHandlers()`: Retrieves both maps and their corresponding handlers.
    * `FindHandlerForMap()`: Finds the handler associated with a specific map.
    * `GetName()`: Retrieves the name associated with the feedback (e.g., property name).
    * `GetKeyedAccessLoadMode()`/`GetKeyedAccessStoreMode()`:  Determines the optimized access mode for keyed property access.
    * `GetKeyType()`:  Indicates whether the keyed access is for a property or an element.
    * `GetBinaryOperationFeedback()`/`GetCompareOperationFeedback()`/`GetTypeOfFeedback()`/`GetForInFeedback()`: Retrieves feedback for specific operation types.
    * `GetConstructorFeedback()`: Retrieves feedback related to `instanceof` checks.
    * `FeedbackIterator`: A helper class to iterate through the feedback data (maps and handlers).

3. **Relate to JavaScript Functionality:**  Consider how these C++ concepts map to JavaScript behavior. For example:

    * Property access (`.`, `[]`) relates to the IC mechanisms.
    * Function calls involve call ICs and speculation.
    * Object cloning.
    * `instanceof` operator.
    * Binary and comparison operators.
    * `typeof` operator.
    * `for...in` loops.

4. **Provide JavaScript Examples:** Create simple JavaScript code snippets that demonstrate the scenarios where the IC mechanisms described in the C++ code would come into play.

5. **Identify Potential Programming Errors:** Think about common mistakes developers make that these ICs are designed to handle and optimize (or deoptimize from):

    * Accessing properties on objects with different shapes.
    * Calling functions with arguments of different types.
    * Using the `instanceof` operator with unexpected types.

6. **Infer Logic and Provide Examples:**  For some methods, it's possible to infer the flow based on the code. For instance, in `ConfigureCloneObject`, the transition from monomorphic to polymorphic caching when different map types are encountered can be illustrated with example inputs and outputs (though "output" here refers to the internal state change of the feedback).

7. **Address the Specific Constraints:**

    * **".tq" extension:**  Explicitly state that the file is `.cc` and therefore *not* a Torque file.
    * **Part 2 of 2:** Acknowledge this and focus on summarizing the *overall* functionality, integrating the understanding gained from part 1 (even though part 1 wasn't provided in the prompt, the instruction implies it).
    * **Summarize Functionality:**  Provide a concise overview of the code's purpose and how it contributes to V8's optimization strategy.

8. **Structure the Output:** Organize the information logically with clear headings and bullet points for readability. Start with a high-level summary and then delve into the details of each method.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on the low-level details of bit manipulation within methods like `ConfigureLexicalVarMode`. I need to step back and explain the *purpose* rather than just the implementation details.
* The relationship between IC states (uninitialized, monomorphic, polymorphic, megamorphic) and how the methods facilitate these transitions is crucial to highlight.
* Ensuring the JavaScript examples are clear and directly relevant to the C++ code is important. Avoid overly complex examples.
* Double-checking the logic inferences and ensuring the assumed inputs and outputs are consistent with the code's behavior.

By following these steps and iterating on the explanations, the comprehensive summary can be generated.
这是对 `v8/src/objects/feedback-vector.cc` 文件代码片段的功能归纳：

**核心功能：管理和操作反馈信息，用于优化 JavaScript 代码的执行效率。**

这段代码主要关注 `FeedbackNexus` 类，它负责管理与特定代码位置（通常是调用点或属性访问点）关联的反馈信息。这些反馈信息是 V8 引擎在执行 JavaScript 代码时收集的，用于指导后续的优化决策，例如内联缓存（Inline Caches, ICs）。

**具体功能点：**

* **获取内联缓存状态 (`GetInlineCacheState`)：**  根据反馈信息判断当前内联缓存的状态，例如：
    * `UNINITIALIZED`: 尚未收集到任何反馈。
    * `MONOMORPHIC`: 只观察到一个接收者类型。
    * `POLYMORPHIC`: 观察到多个接收者类型。
    * `MEGAMORPHIC`: 观察到非常多的接收者类型。
    * `GENERIC`: 退化到通用状态。

* **配置内联缓存模式：**  提供多种方法来配置内联缓存的行为，根据不同的操作类型和收集到的反馈进行设置：
    * `ConfigurePropertyCellMode`:  针对全局属性访问，关联一个 `PropertyCell`。
    * `ConfigureLexicalVarMode`: 针对词法变量访问，存储变量在上下文中的索引和是否可变的信息。
    * `ConfigureHandlerMode`:  配置一个通用的处理器，通常用于处理多种情况，例如 `MEGAMORPHIC` 状态。
    * `ConfigureCloneObject`:  管理对象克隆操作的反馈，记录已遇到的对象映射关系。
    * `ConfigureMonomorphic`:  当只遇到一种接收者类型时，配置单态内联缓存。
    * `ConfigurePolymorphic`: 当遇到多种接收者类型时，配置多态内联缓存。

* **管理调用计数和推测模式（针对函数调用）：**
    * `GetCallCount`: 获取函数被调用的次数。
    * `SetSpeculationMode`/`GetSpeculationMode`:  设置和获取函数调用的推测模式，用于指导优化。
    * `GetCallFeedbackContent`: 获取调用反馈内容的附加信息。
    * `ComputeCallFrequency`: 计算函数调用的频率。

* **提取反馈信息：** 提供方法来获取存储的反馈信息，用于分析和优化：
    * `ExtractMaps`:  提取已观察到的对象 `Map` (可以理解为对象的“形状”)。
    * `ExtractMegaDOMHandler`:  提取用于处理巨型 DOM 对象的处理器。
    * `ExtractMapsAndHandlers`: 提取已观察到的对象 `Map` 和与之关联的处理函数（handler）。
    * `FindHandlerForMap`:  根据 `Map` 查找对应的处理函数。
    * `GetName`:  获取与反馈关联的名称 (例如属性名)。

* **获取键控访问模式（针对属性/元素访问）：**
    * `GetKeyedAccessLoadMode`: 获取键控加载操作的访问模式。
    * `GetKeyedAccessStoreMode`: 获取键控存储操作的访问模式。
    * `GetKeyType`:  判断键控访问是针对属性还是数组元素。

* **获取其他操作的反馈信息：**
    * `GetBinaryOperationFeedback`: 获取二元运算的反馈信息。
    * `GetCompareOperationFeedback`: 获取比较运算的反馈信息。
    * `GetTypeOfFeedback`: 获取 `typeof` 运算符的反馈信息。
    * `GetForInFeedback`: 获取 `for...in` 循环的反馈信息。
    * `GetConstructorFeedback`: 获取 `instanceof` 运算符的反馈信息。

* **迭代反馈信息 (`FeedbackIterator`)：**  提供一个迭代器，用于遍历存储在 `FeedbackNexus` 中的 `Map` 和处理函数。

**与 JavaScript 功能的关系及举例：**

这段代码与 JavaScript 代码的性能优化密切相关。它通过收集运行时信息，使得 V8 能够对常见的操作进行优化。

**例子：属性访问优化**

```javascript
function getProperty(obj) {
  return obj.x;
}

const obj1 = { x: 1, y: 2 };
const obj2 = { x: "hello", z: 3 };

getProperty(obj1); // 第一次调用，可能触发内联缓存初始化
getProperty(obj1); // 第二次调用，如果 obj 的 "形状" 相同，可能会命中单态内联缓存
getProperty(obj2); // 第三次调用，obj 的 "形状" 不同，可能会导致内联缓存变成多态
```

在这个例子中，`FeedbackNexus` 会记录 `getProperty` 函数中访问 `obj.x` 时遇到的 `obj` 的类型（更准确地说是 `Map`）。

* 第一次调用 `getProperty(obj1)` 时，`FeedbackNexus` 可能会记录 `obj1` 的 `Map`，并将内联缓存状态设置为 `MONOMORPHIC`。
* 第二次调用时，如果传入的仍然是具有相同 `Map` 的对象，则可以直接使用缓存的信息，提高访问速度。
* 第三次调用 `getProperty(obj2)` 时，由于 `obj2` 的 `Map` 与之前不同，`FeedbackNexus` 会更新反馈信息，内联缓存状态可能变为 `POLYMORPHIC`，存储多个 `Map` 和对应的访问方式。

**代码逻辑推理：假设输入与输出**

假设我们有一个 `FeedbackNexus` 对象 `nexus`，用于优化以下代码的属性访问：

```javascript
function accessProperty(obj) {
  return obj.name;
}
```

**假设输入：**

1. 第一次调用 `accessProperty({ name: "Alice" })`。
2. 第二次调用 `accessProperty({ name: "Bob", age: 30 })`。

**可能的输出（内部状态变化）：**

1. **第一次调用后：**
   * `nexus->GetInlineCacheState()` 可能返回 `InlineCacheState::MONOMORPHIC`。
   * `nexus` 内部会存储 `{ name: "Alice" }` 对象的 `Map`。

2. **第二次调用后：**
   * `nexus->GetInlineCacheState()` 可能返回 `InlineCacheState::POLYMORPHIC`。
   * `nexus` 内部会存储一个包含两个条目的数据结构，分别对应 `{ name: "Alice" }` 和 `{ name: "Bob", age: 30 }` 的 `Map`，以及对应的属性访问方式。

**用户常见的编程错误：**

内联缓存的优化依赖于代码执行路径的稳定性和对象形状的一致性。以下是一些可能导致内联缓存失效或性能下降的常见编程错误：

* **频繁修改对象的形状：**  动态添加或删除对象的属性会导致对象 `Map` 的改变，使得单态内联缓存失效，甚至导致多态内联缓存的性能下降。

   ```javascript
   function processObject(obj) {
     return obj.value;
   }

   const obj = { value: 1 };
   processObject(obj); // 触发单态内联缓存

   obj.extra = 2; // 修改了 obj 的形状
   processObject(obj); // 可能导致内联缓存失效或降级
   ```

* **在循环中处理不同形状的对象：** 如果在一个循环中处理的对象具有不同的属性结构，会导致内联缓存不断地更新，反而降低性能。

   ```javascript
   const objects = [{ x: 1 }, { x: 2, y: 3 }, { x: 4 }];
   for (const obj of objects) {
     console.log(obj.x); // 这里的属性访问可能难以优化
   }
   ```

* **过度使用动态特性：**  过度依赖 JavaScript 的动态特性，例如在运行时动态创建属性，会使得 V8 难以进行静态分析和优化。

**归纳其功能 (作为第 2 部分)：**

作为第二部分，可以总结 `v8/src/objects/feedback-vector.cc` (特别是其中的 `FeedbackNexus` 类) 的核心功能是 **为 V8 引擎提供一个机制来收集、存储和利用 JavaScript 代码运行时的反馈信息，以便进行动态优化**。 这部分代码定义了如何表示和操作这些反馈信息，包括内联缓存的状态管理、不同操作类型的反馈配置和提取，以及用于遍历反馈数据的迭代器。  它支撑了 V8 引擎的关键优化策略，使得 JavaScript 代码能够更高效地执行。

请注意，由于这是一个 C++ 文件，它不是 Torque 源代码。 Torque 文件以 `.tq` 结尾。

### 提示词
```
这是目录为v8/src/objects/feedback-vector.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/feedback-vector.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
}
      if (feedback.IsWeakOrCleared()) {
        return InlineCacheState::MONOMORPHIC;
      }

      DCHECK(IsWeakFixedArray(feedback.GetHeapObjectAssumeStrong()));
      return InlineCacheState::POLYMORPHIC;
    }

    case FeedbackSlotKind::kInvalid:
      UNREACHABLE();
  }
  return InlineCacheState::UNINITIALIZED;
}

void FeedbackNexus::ConfigurePropertyCellMode(DirectHandle<PropertyCell> cell) {
  DCHECK(IsGlobalICKind(kind()));
  SetFeedback(MakeWeak(*cell), UPDATE_WRITE_BARRIER, UninitializedSentinel(),
              SKIP_WRITE_BARRIER);
}

#if DEBUG
namespace {
bool shouldStressLexicalIC(int script_context_index, int context_slot_index) {
  return (script_context_index + context_slot_index) % 100 == 0;
}
}  // namespace
#endif

bool FeedbackNexus::ConfigureLexicalVarMode(int script_context_index,
                                            int context_slot_index,
                                            bool immutable) {
  DCHECK(IsGlobalICKind(kind()));
  DCHECK_LE(0, script_context_index);
  DCHECK_LE(0, context_slot_index);
#if DEBUG
  if (v8_flags.stress_ic &&
      shouldStressLexicalIC(script_context_index, context_slot_index)) {
    return false;
  }
#endif
  if (!ContextIndexBits::is_valid(script_context_index) ||
      !SlotIndexBits::is_valid(context_slot_index) ||
      !ImmutabilityBit::is_valid(immutable)) {
    return false;
  }
  int config = ContextIndexBits::encode(script_context_index) |
               SlotIndexBits::encode(context_slot_index) |
               ImmutabilityBit::encode(immutable);

  SetFeedback(Smi::From31BitPattern(config), SKIP_WRITE_BARRIER,
              UninitializedSentinel(), SKIP_WRITE_BARRIER);
  return true;
}

void FeedbackNexus::ConfigureHandlerMode(const MaybeObjectHandle& handler) {
  DCHECK(IsGlobalICKind(kind()));
  DCHECK(IC::IsHandler(*handler));
  SetFeedback(ClearedValue(config()->isolate()), UPDATE_WRITE_BARRIER, *handler,
              UPDATE_WRITE_BARRIER);
}

void FeedbackNexus::ConfigureCloneObject(
    Handle<Map> source_map, const MaybeObjectHandle& handler_handle) {
  // TODO(olivf): Introduce a CloneHandler to deal with all the logic of this
  // state machine which is now spread between Runtime_CloneObjectIC_Miss and
  // this method.
  auto GetHandler = [=]() {
    if (IsSmi(*handler_handle)) {
      return *handler_handle;
    }
    return MakeWeak(*handler_handle);
  };
  DCHECK(config()->can_write());
  Isolate* isolate = config()->isolate();
  Handle<HeapObject> feedback;
  {
    Tagged<MaybeObject> maybe_feedback = GetFeedback();
    if (maybe_feedback.IsStrongOrWeak()) {
      feedback = handle(maybe_feedback.GetHeapObject(), isolate);
    } else {
      DCHECK(maybe_feedback.IsCleared());
    }
  }
  switch (ic_state()) {
    case InlineCacheState::UNINITIALIZED:
      // Cache the first map seen which meets the fast case requirements.
      SetFeedback(MakeWeak(*source_map), UPDATE_WRITE_BARRIER, GetHandler());
      break;
    case InlineCacheState::MONOMORPHIC:
      if (feedback.is_null() || feedback.is_identical_to(source_map) ||
          Cast<Map>(*feedback)->is_deprecated()) {
        SetFeedback(MakeWeak(*source_map), UPDATE_WRITE_BARRIER, GetHandler());
      } else {
        // Transition to POLYMORPHIC.
        DirectHandle<WeakFixedArray> array =
            CreateArrayOfSize(2 * kCloneObjectPolymorphicEntrySize);
        DisallowGarbageCollection no_gc;
        Tagged<WeakFixedArray> raw_array = *array;
        raw_array->set(0, MakeWeak(*feedback));
        raw_array->set(1, GetFeedbackExtra());
        raw_array->set(2, MakeWeak(*source_map));
        raw_array->set(3, GetHandler());
        SetFeedback(raw_array, UPDATE_WRITE_BARRIER, ClearedValue(isolate));
      }
      break;
    case InlineCacheState::POLYMORPHIC: {
      const int kMaxElements = v8_flags.max_valid_polymorphic_map_count *
                               kCloneObjectPolymorphicEntrySize;
      DirectHandle<WeakFixedArray> array = Cast<WeakFixedArray>(feedback);
      int i = 0;
      for (; i < array->length(); i += kCloneObjectPolymorphicEntrySize) {
        Tagged<MaybeObject> feedback_map = array->get(i);
        if (feedback_map.IsCleared()) break;
        Handle<Map> cached_map(Cast<Map>(feedback_map.GetHeapObject()),
                               isolate);
        if (cached_map.is_identical_to(source_map) ||
            cached_map->is_deprecated())
          break;
      }

      if (i >= array->length()) {
        if (i == kMaxElements) {
          // Transition to MEGAMORPHIC.
          Tagged<MaybeObject> sentinel = MegamorphicSentinel();
          SetFeedback(sentinel, SKIP_WRITE_BARRIER, ClearedValue(isolate));
          break;
        }

        // Grow polymorphic feedback array.
        DirectHandle<WeakFixedArray> new_array = CreateArrayOfSize(
            array->length() + kCloneObjectPolymorphicEntrySize);
        for (int j = 0; j < array->length(); ++j) {
          new_array->set(j, array->get(j));
        }
        SetFeedback(*new_array);
        array = new_array;
      }

      array->set(i, MakeWeak(*source_map));
      array->set(i + 1, GetHandler());
      break;
    }

    default:
      UNREACHABLE();
  }
}

int FeedbackNexus::GetCallCount() {
  DCHECK(IsCallICKind(kind()));

  Tagged<Object> call_count = Cast<Object>(GetFeedbackExtra());
  CHECK(IsSmi(call_count));
  uint32_t value = static_cast<uint32_t>(Smi::ToInt(call_count));
  return CallCountField::decode(value);
}

void FeedbackNexus::SetSpeculationMode(SpeculationMode mode) {
  DCHECK(IsCallICKind(kind()));

  Tagged<Object> call_count = Cast<Object>(GetFeedbackExtra());
  CHECK(IsSmi(call_count));
  uint32_t count = static_cast<uint32_t>(Smi::ToInt(call_count));
  count = SpeculationModeField::update(count, mode);
  Tagged<MaybeObject> feedback = GetFeedback();
  // We could've skipped WB here (since we set the slot to the same value again)
  // but we don't to make WB verification happy.
  SetFeedback(feedback, UPDATE_WRITE_BARRIER, Smi::FromInt(count),
              SKIP_WRITE_BARRIER);
}

SpeculationMode FeedbackNexus::GetSpeculationMode() {
  DCHECK(IsCallICKind(kind()));

  Tagged<Object> call_count = Cast<Object>(GetFeedbackExtra());
  CHECK(IsSmi(call_count));
  uint32_t value = static_cast<uint32_t>(Smi::ToInt(call_count));
  return SpeculationModeField::decode(value);
}

CallFeedbackContent FeedbackNexus::GetCallFeedbackContent() {
  DCHECK(IsCallICKind(kind()));

  Tagged<Object> call_count = Cast<Object>(GetFeedbackExtra());
  CHECK(IsSmi(call_count));
  uint32_t value = static_cast<uint32_t>(Smi::ToInt(call_count));
  return CallFeedbackContentField::decode(value);
}

float FeedbackNexus::ComputeCallFrequency() {
  DCHECK(IsCallICKind(kind()));

  double const invocation_count = vector()->invocation_count(kRelaxedLoad);
  double const call_count = GetCallCount();
  if (invocation_count == 0.0) {  // Prevent division by 0.
    return 0.0f;
  }
  return static_cast<float>(call_count / invocation_count);
}

void FeedbackNexus::ConfigureMonomorphic(Handle<Name> name,
                                         DirectHandle<Map> receiver_map,
                                         const MaybeObjectHandle& handler) {
  DCHECK(handler.is_null() || IC::IsHandler(*handler));
  if (kind() == FeedbackSlotKind::kDefineKeyedOwnPropertyInLiteral) {
    SetFeedback(MakeWeak(*receiver_map), UPDATE_WRITE_BARRIER, *name);
  } else {
    if (name.is_null()) {
      SetFeedback(MakeWeak(*receiver_map), UPDATE_WRITE_BARRIER, *handler);
    } else {
      DirectHandle<WeakFixedArray> array = CreateArrayOfSize(2);
      array->set(0, MakeWeak(*receiver_map));
      array->set(1, *handler);
      SetFeedback(*name, UPDATE_WRITE_BARRIER, *array);
    }
  }
}

void FeedbackNexus::ConfigurePolymorphic(
    Handle<Name> name, std::vector<MapAndHandler> const& maps_and_handlers) {
  int receiver_count = static_cast<int>(maps_and_handlers.size());
  DCHECK_GT(receiver_count, 1);
  DirectHandle<WeakFixedArray> array = CreateArrayOfSize(receiver_count * 2);

  for (int current = 0; current < receiver_count; ++current) {
    DirectHandle<Map> map = maps_and_handlers[current].first;
    array->set(current * 2, MakeWeak(*map));
    MaybeObjectHandle handler = maps_and_handlers[current].second;
    DCHECK(IC::IsHandler(*handler));
    array->set(current * 2 + 1, *handler);
  }

  if (name.is_null()) {
    SetFeedback(*array, UPDATE_WRITE_BARRIER, UninitializedSentinel(),
                SKIP_WRITE_BARRIER);
  } else {
    SetFeedback(*name, UPDATE_WRITE_BARRIER, *array);
  }
}

int FeedbackNexus::ExtractMaps(MapHandles* maps) const {
  DisallowGarbageCollection no_gc;
  int found = 0;
  for (FeedbackIterator it(this); !it.done(); it.Advance()) {
    maps->push_back(config()->NewHandle(it.map()));
    found++;
  }

  return found;
}

MaybeObjectHandle FeedbackNexus::ExtractMegaDOMHandler() {
  DCHECK(ic_state() == InlineCacheState::MEGADOM);
  DisallowGarbageCollection no_gc;

  auto pair = GetFeedbackPair();
  Tagged<MaybeObject> maybe_handler = pair.second;
  if (!maybe_handler.IsCleared()) {
    MaybeObjectHandle handler = config()->NewHandle(maybe_handler);
    return handler;
  }

  return MaybeObjectHandle();
}

int FeedbackNexus::ExtractMapsAndHandlers(
    std::vector<MapAndHandler>* maps_and_handlers,
    TryUpdateHandler map_handler) const {
  DCHECK(!IsDefineKeyedOwnPropertyInLiteralKind(kind()));
  DisallowGarbageCollection no_gc;
  int found = 0;

  for (FeedbackIterator it(this); !it.done(); it.Advance()) {
    Handle<Map> map = config()->NewHandle(it.map());
    Tagged<MaybeObject> maybe_handler = it.handler();
    if (!maybe_handler.IsCleared()) {
      DCHECK(IC::IsHandler(maybe_handler));
      MaybeObjectHandle handler = config()->NewHandle(maybe_handler);
      if (map_handler && !(map_handler(map).ToHandle(&map))) {
        continue;
      }
      maps_and_handlers->push_back(MapAndHandler(map, handler));
      found++;
    }
  }

  return found;
}

MaybeObjectHandle FeedbackNexus::FindHandlerForMap(
    DirectHandle<Map> map) const {
  DCHECK(!IsStoreInArrayLiteralICKind(kind()));

  for (FeedbackIterator it(this); !it.done(); it.Advance()) {
    if (it.map() == *map && !it.handler().IsCleared()) {
      return config()->NewHandle(it.handler());
    }
  }
  return MaybeObjectHandle();
}

Tagged<Name> FeedbackNexus::GetName() const {
  if (IsKeyedStoreICKind(kind()) || IsKeyedLoadICKind(kind()) ||
      IsKeyedHasICKind(kind()) || IsDefineKeyedOwnICKind(kind())) {
    Tagged<MaybeObject> feedback = GetFeedback();
    if (IsPropertyNameFeedback(feedback)) {
      return Cast<Name>(feedback.GetHeapObjectAssumeStrong());
    }
  }
  if (IsDefineKeyedOwnPropertyInLiteralKind(kind())) {
    Tagged<MaybeObject> extra = GetFeedbackExtra();
    if (IsPropertyNameFeedback(extra)) {
      return Cast<Name>(extra.GetHeapObjectAssumeStrong());
    }
  }
  return {};
}

KeyedAccessLoadMode FeedbackNexus::GetKeyedAccessLoadMode() const {
  DCHECK(IsKeyedLoadICKind(kind()) || IsKeyedHasICKind(kind()));
  // TODO(victorgomes): The KeyedAccessLoadMode::kInBounds is doing double duty
  // here. It shouldn't be used for property loads.
  if (GetKeyType() == IcCheckType::kProperty) {
    return KeyedAccessLoadMode::kInBounds;
  }
  std::vector<MapAndHandler> maps_and_handlers;
  ExtractMapsAndHandlers(&maps_and_handlers);
  KeyedAccessLoadMode mode = KeyedAccessLoadMode::kInBounds;
  for (MapAndHandler map_and_handler : maps_and_handlers) {
    mode = GeneralizeKeyedAccessLoadMode(
        mode, LoadHandler::GetKeyedAccessLoadMode(*map_and_handler.second));
  }
  return mode;
}

namespace {

bool BuiltinHasKeyedAccessStoreMode(Builtin builtin) {
  DCHECK(Builtins::IsBuiltinId(builtin));
  switch (builtin) {
    case Builtin::kKeyedStoreIC_SloppyArguments_InBounds:
    case Builtin::kKeyedStoreIC_SloppyArguments_NoTransitionGrowAndHandleCOW:
    case Builtin::kKeyedStoreIC_SloppyArguments_NoTransitionIgnoreTypedArrayOOB:
    case Builtin::kKeyedStoreIC_SloppyArguments_NoTransitionHandleCOW:
    case Builtin::kStoreFastElementIC_InBounds:
    case Builtin::kStoreFastElementIC_NoTransitionGrowAndHandleCOW:
    case Builtin::kStoreFastElementIC_NoTransitionIgnoreTypedArrayOOB:
    case Builtin::kStoreFastElementIC_NoTransitionHandleCOW:
    case Builtin::kElementsTransitionAndStore_InBounds:
    case Builtin::kElementsTransitionAndStore_NoTransitionGrowAndHandleCOW:
    case Builtin::kElementsTransitionAndStore_NoTransitionIgnoreTypedArrayOOB:
    case Builtin::kElementsTransitionAndStore_NoTransitionHandleCOW:
      return true;
    default:
      return false;
  }
  UNREACHABLE();
}

KeyedAccessStoreMode KeyedAccessStoreModeForBuiltin(Builtin builtin) {
  DCHECK(BuiltinHasKeyedAccessStoreMode(builtin));
  switch (builtin) {
    case Builtin::kKeyedStoreIC_SloppyArguments_InBounds:
    case Builtin::kStoreFastElementIC_InBounds:
    case Builtin::kElementsTransitionAndStore_InBounds:
      return KeyedAccessStoreMode::kInBounds;
    case Builtin::kKeyedStoreIC_SloppyArguments_NoTransitionGrowAndHandleCOW:
    case Builtin::kStoreFastElementIC_NoTransitionGrowAndHandleCOW:
    case Builtin::kElementsTransitionAndStore_NoTransitionGrowAndHandleCOW:
      return KeyedAccessStoreMode::kGrowAndHandleCOW;
    case Builtin::kKeyedStoreIC_SloppyArguments_NoTransitionIgnoreTypedArrayOOB:
    case Builtin::kStoreFastElementIC_NoTransitionIgnoreTypedArrayOOB:
    case Builtin::kElementsTransitionAndStore_NoTransitionIgnoreTypedArrayOOB:
      return KeyedAccessStoreMode::kIgnoreTypedArrayOOB;
    case Builtin::kKeyedStoreIC_SloppyArguments_NoTransitionHandleCOW:
    case Builtin::kStoreFastElementIC_NoTransitionHandleCOW:
    case Builtin::kElementsTransitionAndStore_NoTransitionHandleCOW:
      return KeyedAccessStoreMode::kHandleCOW;
    default:
      UNREACHABLE();
  }
}

}  // namespace

KeyedAccessStoreMode FeedbackNexus::GetKeyedAccessStoreMode() const {
  DCHECK(IsKeyedStoreICKind(kind()) || IsStoreInArrayLiteralICKind(kind()) ||
         IsDefineKeyedOwnPropertyInLiteralKind(kind()) ||
         IsDefineKeyedOwnICKind(kind()));
  KeyedAccessStoreMode mode = KeyedAccessStoreMode::kInBounds;

  if (GetKeyType() == IcCheckType::kProperty) return mode;

  std::vector<MapAndHandler> maps_and_handlers;
  ExtractMapsAndHandlers(&maps_and_handlers);
  for (const MapAndHandler& map_and_handler : maps_and_handlers) {
    const MaybeObjectHandle maybe_code_handler = map_and_handler.second;
    // The first handler that isn't the slow handler will have the bits we need.
    Builtin builtin_handler = Builtin::kNoBuiltinId;
    if (IsStoreHandler(*maybe_code_handler.object())) {
      auto data_handler = Cast<StoreHandler>(maybe_code_handler.object());

      if (IsSmi(data_handler->smi_handler())) {
        // Decode the KeyedAccessStoreMode information from the Handler.
        mode =
            StoreHandler::GetKeyedAccessStoreMode(data_handler->smi_handler());
        if (!StoreModeIsInBounds(mode)) return mode;
        continue;
      } else {
        Tagged<Code> code = Cast<Code>(data_handler->smi_handler());
        builtin_handler = code->builtin_id();
      }

    } else if (IsSmi(*maybe_code_handler.object())) {
      // Skip for Proxy Handlers.
      if (*maybe_code_handler.object() == StoreHandler::StoreProxy()) {
        continue;
      }
      // Decode the KeyedAccessStoreMode information from the Handler.
      mode = StoreHandler::GetKeyedAccessStoreMode(*maybe_code_handler);
      if (!StoreModeIsInBounds(mode)) return mode;
      continue;
    } else if (IsDefineKeyedOwnICKind(kind())) {
      mode = StoreHandler::GetKeyedAccessStoreMode(*maybe_code_handler);
      if (!StoreModeIsInBounds(mode)) return mode;
      continue;
    } else {
      // Element store without prototype chain check.
      Tagged<Code> code = Cast<Code>(*maybe_code_handler.object());
      builtin_handler = code->builtin_id();
    }

    if (Builtins::IsBuiltinId(builtin_handler)) {
      if (!BuiltinHasKeyedAccessStoreMode(builtin_handler)) continue;

      mode = KeyedAccessStoreModeForBuiltin(builtin_handler);
      break;
    }
  }

  return mode;
}

IcCheckType FeedbackNexus::GetKeyType() const {
  DCHECK(IsKeyedStoreICKind(kind()) || IsKeyedLoadICKind(kind()) ||
         IsStoreInArrayLiteralICKind(kind()) || IsKeyedHasICKind(kind()) ||
         IsDefineKeyedOwnPropertyInLiteralKind(kind()) ||
         IsDefineKeyedOwnICKind(kind()));
  auto pair = GetFeedbackPair();
  Tagged<MaybeObject> feedback = pair.first;
  if (feedback == MegamorphicSentinel()) {
    return static_cast<IcCheckType>(Smi::ToInt(Cast<Smi>(pair.second)));
  }
  Tagged<MaybeObject> maybe_name =
      IsDefineKeyedOwnPropertyInLiteralKind(kind()) ||
              IsDefineKeyedOwnICKind(kind())
          ? pair.second
          : feedback;
  return IsPropertyNameFeedback(maybe_name) ? IcCheckType::kProperty
                                            : IcCheckType::kElement;
}

BinaryOperationHint FeedbackNexus::GetBinaryOperationFeedback() const {
  DCHECK_EQ(kind(), FeedbackSlotKind::kBinaryOp);
  int feedback = GetFeedback().ToSmi().value();
  return BinaryOperationHintFromFeedback(feedback);
}

CompareOperationHint FeedbackNexus::GetCompareOperationFeedback() const {
  DCHECK_EQ(kind(), FeedbackSlotKind::kCompareOp);
  int feedback = GetFeedback().ToSmi().value();
  return CompareOperationHintFromFeedback(feedback);
}

TypeOfFeedback::Result FeedbackNexus::GetTypeOfFeedback() const {
  DCHECK_EQ(kind(), FeedbackSlotKind::kTypeOf);
  return static_cast<TypeOfFeedback::Result>(GetFeedback().ToSmi().value());
}

ForInHint FeedbackNexus::GetForInFeedback() const {
  DCHECK_EQ(kind(), FeedbackSlotKind::kForIn);
  int feedback = GetFeedback().ToSmi().value();
  return ForInHintFromFeedback(static_cast<ForInFeedback>(feedback));
}

MaybeHandle<JSObject> FeedbackNexus::GetConstructorFeedback() const {
  DCHECK_EQ(kind(), FeedbackSlotKind::kInstanceOf);
  Tagged<MaybeObject> feedback = GetFeedback();
  Tagged<HeapObject> heap_object;
  if (feedback.GetHeapObjectIfWeak(&heap_object)) {
    return config()->NewHandle(Cast<JSObject>(heap_object));
  }
  return MaybeHandle<JSObject>();
}

FeedbackIterator::FeedbackIterator(const FeedbackNexus* nexus)
    : done_(false), index_(-1), state_(kOther) {
  DCHECK(
      IsLoadICKind(nexus->kind()) || IsSetNamedICKind(nexus->kind()) ||
      IsKeyedLoadICKind(nexus->kind()) || IsKeyedStoreICKind(nexus->kind()) ||
      IsDefineNamedOwnICKind(nexus->kind()) ||
      IsDefineKeyedOwnPropertyInLiteralKind(nexus->kind()) ||
      IsStoreInArrayLiteralICKind(nexus->kind()) ||
      IsKeyedHasICKind(nexus->kind()) || IsDefineKeyedOwnICKind(nexus->kind()));

  DisallowGarbageCollection no_gc;
  auto pair = nexus->GetFeedbackPair();
  Tagged<MaybeObject> feedback = pair.first;
  bool is_named_feedback = IsPropertyNameFeedback(feedback);
  Tagged<HeapObject> heap_object;

  if ((feedback.GetHeapObjectIfStrong(&heap_object) &&
       IsWeakFixedArray(heap_object)) ||
      is_named_feedback) {
    index_ = 0;
    state_ = kPolymorphic;
    heap_object = feedback.GetHeapObjectAssumeStrong();
    if (is_named_feedback) {
      polymorphic_feedback_ = nexus->config()->NewHandle(
          Cast<WeakFixedArray>(pair.second.GetHeapObjectAssumeStrong()));
    } else {
      polymorphic_feedback_ =
          nexus->config()->NewHandle(Cast<WeakFixedArray>(heap_object));
    }
    AdvancePolymorphic();
  } else if (feedback.GetHeapObjectIfWeak(&heap_object)) {
    state_ = kMonomorphic;
    Tagged<MaybeObject> handler = pair.second;
    map_ = Cast<Map>(heap_object);
    handler_ = handler;
  } else {
    done_ = true;
  }
}

void FeedbackIterator::Advance() {
  CHECK(!done_);

  if (state_ == kMonomorphic) {
    done_ = true;
    return;
  }

  CHECK_EQ(state_, kPolymorphic);
  AdvancePolymorphic();
}

void FeedbackIterator::AdvancePolymorphic() {
  CHECK(!done_);
  CHECK_EQ(state_, kPolymorphic);
  int length = polymorphic_feedback_->length();
  Tagged<HeapObject> heap_object;

  while (index_ < length) {
    if (polymorphic_feedback_->get(index_).GetHeapObjectIfWeak(&heap_object)) {
      Tagged<MaybeObject> handler =
          polymorphic_feedback_->get(index_ + kHandlerOffset);
      map_ = Cast<Map>(heap_object);
      handler_ = handler;
      index_ += kEntrySize;
      return;
    }
    index_ += kEntrySize;
  }

  CHECK_EQ(index_, length);
  done_ = true;
}
}  // namespace v8::internal
```