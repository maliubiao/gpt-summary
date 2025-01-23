Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is part of the V8 JavaScript engine and is located in a test file.

Here's a breakdown of how to address each of the user's requests:

1. **List the functionality:** Analyze the code to understand its purpose. It involves testing how field types are tracked and how they generalize during transitions between object maps.

2. **Check for Torque source:** Examine the file extension. It's `.cc`, not `.tq`, so it's C++.

3. **Relate to JavaScript:** Explain how the concepts tested in the C++ code relate to JavaScript behavior, specifically how JavaScript engines optimize object property access by tracking their types.

4. **Provide JavaScript examples:**  Create simple JavaScript code snippets that illustrate the concepts being tested in the C++ code, such as adding properties with different types.

5. **Code logic reasoning with input/output:**  For specific test cases (like `TestGeneralizeFieldWithSpecialTransition`), describe a scenario with a starting object structure and how the field types might evolve through transitions.

6. **Common programming errors:**  Identify common JavaScript mistakes that could trigger the type transitions being tested, such as assigning values of different types to the same property.

7. **Summarize the functionality (Part 4 of 5):**  Combine the above points into a concise summary, noting that this is part 4 of a larger test suite.

**Constraint Checklist & Confidence Score:**

1. 列举一下它的功能: Yes
2. 如果v8/test/cctest/test-field-type-tracking.cc以.tq结尾，那它是个v8 torque源代码: Yes
3. 如果它与javascript的功能有关系，请用javascript举例说明: Yes
4. 如果有代码逻辑推理，请给出假设输入与输出: Yes
5. 如果涉及用户常见的编程错误，请举例说明: Yes
6. 这是第4部分，共5部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

**Mental Sandbox:**

* **Core Functionality:** The code is about testing the generalization of field types in V8 object maps. This is crucial for optimization.
* **`.tq` check:**  Simple file extension check.
* **JavaScript connection:** Need to explain the concept of hidden classes/maps and how type changes trigger transitions.
* **JavaScript examples:**  Focus on type changes in object properties.
* **Logic reasoning:**  Pick a test case and show how a field's representation can change. For example, going from Smi to Double, then to Tagged.
* **Common errors:**  Reassigning properties with different types is the most obvious example.
* **Summary for Part 4:**  Emphasize the testing of more complex transitions involving special operations like prototype changes and element kind changes. Also, the handling of legacy scenarios (when a specific flag is not enabled).

Strategizing complete. Proceeding with response generation.

这是一个V8源代码文件，位于 `v8/test/cctest/` 目录下，并且文件名是 `test-field-type-tracking.cc`，因此它是一个 **C++** 源代码文件，用于测试 V8 引擎中 **字段类型跟踪 (field type tracking)** 的功能。

**功能列举:**

这个代码片段主要包含了一系列的单元测试，用于验证 V8 在以下场景中如何跟踪和泛化对象字段的类型：

1. **基本类型泛化:** 测试当对象字段的值类型发生变化时，V8 如何更新其内部表示 (Representation)。例如，从 `Smi` (小整数) 泛化到 `Double` (浮点数)，再到 `Tagged` (可以指向任何 V8 堆对象的指针)。
2. **常量属性:** 测试常量属性的类型跟踪和泛化。
3. **特殊的转换 (Special Transitions):**  测试在执行特殊操作（例如，更改对象的原型、更改元素的种类 (ElementsKind)）时，字段类型的泛化行为。
4. **是否拥有描述符 (Owning Descriptors):**  测试对象 Map 是否拥有描述符 (descriptors) 对字段类型泛化的影响。拥有描述符意味着 Map 存储了属性的完整信息，而不拥有则可能需要查找原型链。
5. **原型转换 (Prototype Transitions):** 测试当对象的原型发生变化时，字段类型的泛化行为。
6. **元素种类转换 (Elements Kind Transitions):** 测试当数组或对象的元素种类发生变化时（例如，从 `PACKED_SMI_ELEMENTS` 到 `PACKED_DOUBLE_ELEMENTS`），字段类型的泛化行为。
7. **属性配置 (Property Reconfiguration):** 测试更改现有属性的特性（例如，从数据属性更改为访问器属性）如何影响类型跟踪。
8. **惰性更新 (Lazy Updates):** 测试类型泛化是否会正确地传播到转换树的其他分支。
9. **对已弃用 Map 的更新 (Update of Deprecated Maps):**  测试当一个 Map 因为类型泛化而被弃用后，如何更新到新的 Map。

**关于文件后缀:**

你提到如果文件名以 `.tq` 结尾，那就是 V8 Torque 源代码。在这个例子中，文件名是 `.cc`，所以它是 C++ 源代码。Torque 是一种 V8 内部使用的类型化的中间语言，用于生成高效的 JavaScript 内置函数。

**与 JavaScript 的关系及示例:**

字段类型跟踪是 V8 引擎为了优化 JavaScript 代码执行而进行的一项关键技术。JavaScript 是一种动态类型语言，这意味着对象的属性可以在运行时存储不同类型的值。为了提高性能，V8 会尝试跟踪对象的属性类型，并基于这些类型信息进行优化，例如内联缓存 (Inline Caches)。

当您在 JavaScript 中对同一个对象的属性赋予不同类型的值时，V8 内部会进行类型泛化，这在 C++ 代码中通过 `TestGeneralizeFieldWithSpecialTransition` 等测试进行验证。

**JavaScript 示例:**

```javascript
// 初始状态，V8 可能认为 x 是一个 Smi (小整数)
const obj = { x: 1 };

// 后来，x 被赋值为浮点数，V8 会将 x 的类型泛化为 Double
obj.x = 1.5;

// 再后来，x 被赋值为字符串，V8 会将 x 的类型泛化为可以存储任何类型的 Tagged 指针
obj.x = "hello";

// 尝试将 x 设置为一个对象
obj.x = { y: 2 };
```

在 V8 内部，每当 `obj.x` 的类型发生变化时，V8 可能会更新 `obj` 的隐藏类 (Hidden Class) 或 Map，以便更准确地表示 `x` 的当前类型。`test-field-type-tracking.cc` 中的测试就是模拟和验证这些内部机制。

**代码逻辑推理 (假设输入与输出):**

考虑 `TestGeneralizeFieldWithSpecialTransition` 中的一个示例：

```c++
TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      kDeprecation);
```

**假设输入:**

* 一个 JavaScript 对象，其某个属性最初存储一个 Smi (例如，整数 `1`)。
* 对该属性进行了修改，尝试将其类型更改为 Double (例如，赋值为浮点数 `1.0`)，并且将其常量性设置为 `kConst` (理论上不可变)。

**代码逻辑:**

这个测试模拟了 V8 尝试将一个可变的 Smi 字段泛化为一个常量的 Double 字段的过程。

**预期输出:**

根据测试的定义，预期的结果是：

* 原始的 Map 会被 **弃用 (kDeprecation)**，因为它无法直接支持这种类型的转换（从可变到常量，同时改变表示）。
* 会创建一个新的 Map，其中该字段的表示是 `Double`，常量性仍然是 `kMutable` (因为即使尝试设置为常量，由于之前的状态，可能无法直接转换为常量)。

**用户常见的编程错误:**

在 JavaScript 中，用户经常会无意中改变对象属性的类型，这会导致 V8 进行类型泛化，虽然这是语言的特性，但在某些情况下可能会影响性能。

**示例:**

```javascript
function Point(x, y) {
  this.x = x;
  this.y = y;
}

const p = new Point(1, 2); // V8 可能认为 x 和 y 是 Smi

p.x = 1.5; // x 的类型变为 Double，触发类型泛化

p.y = "hello"; // y 的类型变为 Tagged，再次触发类型泛化
```

这种频繁的类型变化可能会导致 V8 不得不放弃一些优化，因为对象的结构变得不那么稳定。

**功能归纳 (第 4 部分，共 5 部分):**

作为系列测试的第 4 部分，这个代码片段着重于测试 V8 引擎在执行更复杂的对象转换和属性配置操作时，如何正确地跟踪和泛化字段类型。这部分特别关注了以下场景：

* **涉及特殊转换的类型泛化：** 例如，当对象的原型或元素的种类发生变化时，V8 如何处理字段类型的更新。
* **对非拥有描述符的 Map 进行操作：** 测试当 Map 不直接拥有属性的完整描述符时，类型泛化的行为。
* **历史兼容性：**  包含了一些针对旧版本 V8 行为的测试 (带有 `Legacy` 后缀)，用于确保在特定标志未启用时的正确性。

总而言之，这部分测试深入探讨了 V8 引擎在应对更复杂和边缘情况下的字段类型跟踪机制，确保了引擎在各种场景下都能准确地管理对象属性的类型信息，从而为后续的性能优化奠定基础。

### 提示词
```
这是目录为v8/test/cctest/test-field-type-tracking.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-field-type-tracking.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  // HeapObject + HeapObject -> Tagged

  TestGeneralizeFieldWithSpecialTransition(
      config,
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      kFieldOwnerDependency);
  TestGeneralizeFieldWithSpecialTransition(
      config,
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      kFieldOwnerDependency);
  TestGeneralizeFieldWithSpecialTransition(
      config,
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      kFieldOwnerDependency);

  TestGeneralizeFieldWithSpecialTransition(
      config,
      {PropertyConstness::kConst, Representation::HeapObject(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::HeapObject(), any_type},
      kFieldOwnerDependency);
  TestGeneralizeFieldWithSpecialTransition(
      config,
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      kFieldOwnerDependency);
  TestGeneralizeFieldWithSpecialTransition(
      config,
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      kFieldOwnerDependency);

  // Double + HeapObject -> Tagged

  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), any_type},
      {PropertyConstness::kConst, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  // Smi + Double -> Double

  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kConst, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kConst, Representation::Double(), any_type},
      kDeprecation);
  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      kDeprecation);
  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      kDeprecation);
}

TEST(PrototypeTransitionFromMapOwningDescriptor) {
  if (!v8_flags.move_prototype_transitions_first) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  struct TestConfig {
    Handle<JSObject> prototype_;

    TestConfig() {
      Isolate* isolate = CcTest::i_isolate();
      Factory* factory = isolate->factory();
      prototype_ = factory->NewJSObjectFromMap(Map::Create(isolate, 0));
    }

    Handle<Map> Transition(Handle<Map> map, Expectations* expectations) {
      MapUpdater update(CcTest::i_isolate(), map);
      return update.ApplyPrototypeTransition(prototype_);
    }
  } config;

  TestMultiplePrototypeTransitions(isolate, &config);
}

TEST(PrototypeTransitionFromMapNotOwningDescriptor) {
  if (!v8_flags.move_prototype_transitions_first) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  struct TestConfig {
    Handle<JSObject> prototype_;

    TestConfig() {
      Isolate* isolate = CcTest::i_isolate();
      Factory* factory = isolate->factory();
      prototype_ = factory->NewJSObjectFromMap(Map::Create(isolate, 0));
    }

    Handle<Map> Transition(Handle<Map> map, Expectations* expectations) {
      Isolate* isolate = CcTest::i_isolate();
      Handle<FieldType> any_type = FieldType::Any(isolate);

      // Add one more transition to |map| in order to prevent descriptors
      // ownership.
      if (map->owns_descriptors()) {
        Map::CopyWithField(isolate, map, CcTest::MakeString("foo"), any_type,
                           NONE, PropertyConstness::kMutable,
                           Representation::Smi(), INSERT_TRANSITION)
            .ToHandleChecked();
      }
      CHECK(!map->owns_descriptors());

      MapUpdater update(isolate, map);
      return update.ApplyPrototypeTransition(prototype_);
    }
  } config;

  TestMultiplePrototypeTransitions(isolate, &config);
}

////////////////////////////////////////////////////////////////////////////////
// A set of tests involving special transitions (such as elements kind
// transition, observed transition or prototype transition).
//
// The following legacy tests are for when
// !v8_flags.move_prototype_transitions_first

// This test ensures that field generalization is correctly propagated from one
// branch of transition tree (|map2|) to another (|map|).
//
//                            p4B: |map2|
//                             |
//                             * - special transition
//                             |
//  {} - p0 - p1 - p2A - p3 - p4A: |map|
//
// where "p4A" and "p4B" are exactly the same properties.
//
// TODO(ishell): unify this test template with
// TestReconfigureDataFieldAttribute_GeneralizeField once
// IS_PROTO_TRANS_ISSUE_FIXED and IS_NON_EQUIVALENT_TRANSITION_SUPPORTED are
// fixed.
template <typename TestConfig>
static void TestGeneralizeFieldWithSpecialTransitionLegacy(
    TestConfig* config, const CRFTData& from, const CRFTData& to,
    const CRFTData& expected, ChangeAlertMechanism expected_alert) {
  if (v8_flags.move_prototype_transitions_first) return;

  Isolate* isolate = CcTest::i_isolate();

  Expectations expectations(isolate);

  // Create a map, add required properties to it and initialize expectations.
  Handle<Map> initial_map = Map::Create(isolate, 0);
  Handle<Map> map = initial_map;
  for (int i = 0; i < kPropCount; i++) {
    map = expectations.AddDataField(map, NONE, from.constness,
                                    from.representation, from.type);
  }
  CHECK(!map->is_deprecated());
  CHECK(map->is_stable());
  CHECK(expectations.Check(*map));

  Expectations expectations2 = expectations;

  // Apply some special transition to |map|.
  CHECK(map->owns_descriptors());
  Handle<Map> map2 = config->Transition(map, &expectations2);

  // |map| should still match expectations.
  CHECK(!map->is_deprecated());
  CHECK(expectations.Check(*map));

  if (config->generalizes_representations()) {
    for (int i = 0; i < kPropCount; i++) {
      expectations2.GeneralizeField(i);
    }
  }

  CHECK(!map2->is_deprecated());
  CHECK(map2->is_stable());
  CHECK(expectations2.Check(*map2));

  // Create new maps by generalizing representation of propX field.
  Handle<Map> maps[kPropCount];
  for (int i = 0; i < kPropCount; i++) {
    Handle<Map> new_map =
        ReconfigureProperty(isolate, map, InternalIndex(i), PropertyKind::kData,
                            NONE, to.representation, to.type);
    maps[i] = new_map;

    expectations.SetDataField(i, expected.constness, expected.representation,
                              expected.type);

    switch (expected_alert) {
      case kDeprecation: {
        CHECK(map->is_deprecated());
        CHECK_NE(*map, *new_map);
        CHECK(i == 0 || maps[i - 1]->is_deprecated());
        CHECK(expectations.Check(*new_map));

        DirectHandle<Map> new_map2 = Map::Update(isolate, map2);
        CHECK(!new_map2->is_deprecated());
        CHECK(!new_map2->is_dictionary_map());

        Handle<Map> tmp_map;
        if (Map::TryUpdate(isolate, map2).ToHandle(&tmp_map)) {
          // If Map::TryUpdate() manages to succeed the result must match the
          // result of Map::Update().
          CHECK_EQ(*new_map2, *tmp_map);
        } else {
          // Equivalent transitions should always find the updated map.
          CHECK(config->is_non_equivalent_transition());
        }

        if (config->is_non_equivalent_transition()) {
          // In case of non-equivalent transition currently we generalize all
          // representations.
          for (int j = 0; j < kPropCount; j++) {
            expectations2.GeneralizeField(j);
          }
          CHECK(IsUndefined(new_map2->GetBackPointer(), isolate));
          CHECK(expectations2.Check(*new_map2));
        } else {
          expectations2.SetDataField(i, expected.constness,
                                     expected.representation, expected.type);

          CHECK(!IsUndefined(new_map2->GetBackPointer(), isolate));
          CHECK(expectations2.Check(*new_map2));
        }
        break;
      }
      case kFieldOwnerDependency: {
        CHECK(!map->is_deprecated());
        // TODO(ishell): Review expectations once IS_PROTO_TRANS_ISSUE_FIXED is
        // removed.
        CHECK(!IS_PROTO_TRANS_ISSUE_FIXED);
        CHECK_EQ(*map, *new_map);
        CHECK(expectations.Check(*new_map));

        CHECK(!map2->is_deprecated());
        CHECK_NE(*map2, *new_map);
        expectations2.SetDataField(i, expected.constness,
                                   expected.representation, expected.type);
        CHECK(expectations2.Check(*map2));
        break;
      }
      case kNoAlert:
        UNREACHABLE();
        break;
    }
  }

  DirectHandle<Map> active_map = maps[kPropCount - 1];
  CHECK(!active_map->is_deprecated());

  // Update all deprecated maps and check that they are now the same.
  DirectHandle<Map> updated_map = Map::Update(isolate, map);
  CHECK_EQ(*active_map, *updated_map);
  CheckMigrationTarget(isolate, *map, *updated_map);
  for (int i = 0; i < kPropCount; i++) {
    updated_map = Map::Update(isolate, maps[i]);
    CHECK_EQ(*active_map, *updated_map);
    CheckMigrationTarget(isolate, *maps[i], *updated_map);
  }
}

TEST(ElementsKindTransitionFromMapOwningDescriptorLegacy) {
  if (v8_flags.move_prototype_transitions_first) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  struct TestConfig {
    TestConfig(PropertyAttributes attributes, Handle<Symbol> symbol,
               ElementsKind kind)
        : attributes(attributes), symbol(symbol), elements_kind(kind) {}

    Handle<Map> Transition(Handle<Map> map, Expectations* expectations) {
      expectations->SetElementsKind(elements_kind);
      expectations->ChangeAttributesForAllProperties(attributes);
      return Map::CopyForPreventExtensions(CcTest::i_isolate(), map, attributes,
                                           symbol, "CopyForPreventExtensions");
    }
    // TODO(ishell): remove once IS_PROTO_TRANS_ISSUE_FIXED is removed.
    bool generalizes_representations() const { return false; }
    bool is_non_equivalent_transition() const { return false; }

    PropertyAttributes attributes;
    Handle<Symbol> symbol;
    ElementsKind elements_kind;
  };
  Factory* factory = isolate->factory();
  TestConfig configs[] = {
      {FROZEN, factory->frozen_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind ? HOLEY_FROZEN_ELEMENTS
                                                   : DICTIONARY_ELEMENTS},
      {SEALED, factory->sealed_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind ? HOLEY_SEALED_ELEMENTS
                                                   : DICTIONARY_ELEMENTS},
      {NONE, factory->nonextensible_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind
           ? HOLEY_NONEXTENSIBLE_ELEMENTS
           : DICTIONARY_ELEMENTS}};
  for (size_t i = 0; i < arraysize(configs); i++) {
    TestGeneralizeFieldWithSpecialTransition(
        &configs[i],
        {PropertyConstness::kMutable, Representation::Smi(), any_type},
        {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
        {PropertyConstness::kMutable, Representation::Tagged(), any_type},
        kFieldOwnerDependency);

    TestGeneralizeFieldWithSpecialTransition(
        &configs[i],
        {PropertyConstness::kMutable, Representation::Double(), any_type},
        {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
        {PropertyConstness::kMutable, Representation::Tagged(), any_type},
        kFieldOwnerDependency);
  }
}

TEST(ElementsKindTransitionFromMapNotOwningDescriptorLegacy) {
  if (v8_flags.move_prototype_transitions_first) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  struct TestConfig {
    TestConfig(PropertyAttributes attributes, Handle<Symbol> symbol,
               ElementsKind kind)
        : attributes(attributes), symbol(symbol), elements_kind(kind) {}

    Handle<Map> Transition(Handle<Map> map, Expectations* expectations) {
      Isolate* isolate = CcTest::i_isolate();
      Handle<FieldType> any_type = FieldType::Any(isolate);

      // Add one more transition to |map| in order to prevent descriptors
      // ownership.
      CHECK(map->owns_descriptors());
      Map::CopyWithField(isolate, map, CcTest::MakeString("foo"), any_type,
                         NONE, PropertyConstness::kMutable,
                         Representation::Smi(), INSERT_TRANSITION)
          .ToHandleChecked();
      CHECK(!map->owns_descriptors());

      expectations->SetElementsKind(elements_kind);
      expectations->ChangeAttributesForAllProperties(attributes);
      return Map::CopyForPreventExtensions(isolate, map, attributes, symbol,
                                           "CopyForPreventExtensions");
    }
    // TODO(ishell): remove once IS_PROTO_TRANS_ISSUE_FIXED is removed.
    bool generalizes_representations() const { return false; }
    bool is_non_equivalent_transition() const { return false; }

    PropertyAttributes attributes;
    Handle<Symbol> symbol;
    ElementsKind elements_kind;
  };
  Factory* factory = isolate->factory();
  TestConfig configs[] = {
      {FROZEN, factory->frozen_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind ? HOLEY_FROZEN_ELEMENTS
                                                   : DICTIONARY_ELEMENTS},
      {SEALED, factory->sealed_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind ? HOLEY_SEALED_ELEMENTS
                                                   : DICTIONARY_ELEMENTS},
      {NONE, factory->nonextensible_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind
           ? HOLEY_NONEXTENSIBLE_ELEMENTS
           : DICTIONARY_ELEMENTS}};
  for (size_t i = 0; i < arraysize(configs); i++) {
    TestGeneralizeFieldWithSpecialTransition(
        &configs[i],
        {PropertyConstness::kMutable, Representation::Smi(), any_type},
        {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
        {PropertyConstness::kMutable, Representation::Tagged(), any_type},
        kFieldOwnerDependency);

    TestGeneralizeFieldWithSpecialTransition(
        &configs[i],
        {PropertyConstness::kMutable, Representation::Double(), any_type},
        {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
        {PropertyConstness::kMutable, Representation::Tagged(), any_type},
        kFieldOwnerDependency);
  }
}

TEST(PrototypeTransitionFromMapOwningDescriptorLegacy) {
  if (v8_flags.move_prototype_transitions_first) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  struct TestConfig {
    Handle<JSObject> prototype_;

    TestConfig() {
      Isolate* isolate = CcTest::i_isolate();
      Factory* factory = isolate->factory();
      prototype_ = factory->NewJSObjectFromMap(Map::Create(isolate, 0));
    }

    Handle<Map> Transition(Handle<Map> map, Expectations* expectations) {
      return Map::TransitionToUpdatePrototype(CcTest::i_isolate(), map,
                                              prototype_);
    }
    // TODO(ishell): remove once IS_PROTO_TRANS_ISSUE_FIXED is removed.
    bool generalizes_representations() const {
      return !IS_PROTO_TRANS_ISSUE_FIXED;
    }
    bool is_non_equivalent_transition() const { return true; }
  };
  TestConfig config;
  TestGeneralizeFieldWithSpecialTransition(
      &config, {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  TestGeneralizeFieldWithSpecialTransition(
      &config,
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
}

TEST(PrototypeTransitionFromMapNotOwningDescriptorLegacy) {
  if (v8_flags.move_prototype_transitions_first) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  struct TestConfig {
    Handle<JSObject> prototype_;

    TestConfig() {
      Isolate* isolate = CcTest::i_isolate();
      Factory* factory = isolate->factory();
      prototype_ = factory->NewJSObjectFromMap(Map::Create(isolate, 0));
    }

    Handle<Map> Transition(Handle<Map> map, Expectations* expectations) {
      Isolate* isolate = CcTest::i_isolate();
      Handle<FieldType> any_type = FieldType::Any(isolate);

      // Add one more transition to |map| in order to prevent descriptors
      // ownership.
      CHECK(map->owns_descriptors());
      Map::CopyWithField(isolate, map, CcTest::MakeString("foo"), any_type,
                         NONE, PropertyConstness::kMutable,
                         Representation::Smi(), INSERT_TRANSITION)
          .ToHandleChecked();
      CHECK(!map->owns_descriptors());

      return Map::TransitionToUpdatePrototype(isolate, map, prototype_);
    }
    // TODO(ishell): remove once IS_PROTO_TRANS_ISSUE_FIXED is removed.
    bool generalizes_representations() const {
      return !IS_PROTO_TRANS_ISSUE_FIXED;
    }
    bool is_non_equivalent_transition() const { return true; }
  };
  TestConfig config;
  TestGeneralizeFieldWithSpecialTransition(
      &config, {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  TestGeneralizeFieldWithSpecialTransition(
      &config,
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
}

////////////////////////////////////////////////////////////////////////////////
// A set of tests for higher level transitioning mechanics.
//

struct TransitionToDataFieldOperator {
  PropertyConstness constness_;
  Representation representation_;
  PropertyAttributes attributes_;
  Handle<FieldType> heap_type_;
  Handle<Object> value_;

  TransitionToDataFieldOperator(PropertyConstness constness,
                                Representation representation,
                                Handle<FieldType> heap_type,
                                Handle<Object> value,
                                PropertyAttributes attributes = NONE)
      : constness_(constness),
        representation_(representation),
        attributes_(attributes),
        heap_type_(heap_type),
        value_(value) {}

  Handle<Map> DoTransition(Expectations* expectations, Handle<Map> map) {
    return expectations->TransitionToDataField(
        map, attributes_, constness_, representation_, heap_type_, value_);
  }
};


struct TransitionToDataConstantOperator {
  PropertyAttributes attributes_;
  Handle<JSFunction> value_;

  TransitionToDataConstantOperator(Handle<JSFunction> value,
                                   PropertyAttributes attributes = NONE)
      : attributes_(attributes), value_(value) {}

  Handle<Map> DoTransition(Expectations* expectations, Handle<Map> map) {
    return expectations->TransitionToDataConstant(map, attributes_, value_);
  }
};


struct TransitionToAccessorConstantOperator {
  PropertyAttributes attributes_;
  Handle<AccessorPair> pair_;

  TransitionToAccessorConstantOperator(Handle<AccessorPair> pair,
                                       PropertyAttributes attributes = NONE)
      : attributes_(attributes), pair_(pair) {}

  Handle<Map> DoTransition(Expectations* expectations, Handle<Map> map) {
    return expectations->TransitionToAccessorConstant(map, attributes_, pair_);
  }
};


struct ReconfigureAsDataPropertyOperator {
  InternalIndex descriptor_;
  Representation representation_;
  PropertyAttributes attributes_;
  Handle<FieldType> heap_type_;

  ReconfigureAsDataPropertyOperator(int descriptor,
                                    Representation representation,
                                    Handle<FieldType> heap_type,
                                    PropertyAttributes attributes = NONE)
      : descriptor_(descriptor),
        representation_(representation),
        attributes_(attributes),
        heap_type_(heap_type) {}

  Handle<Map> DoTransition(Isolate* isolate, Expectations* expectations,
                           Handle<Map> map) {
    expectations->SetDataField(descriptor_.as_int(),
                               PropertyConstness::kMutable, representation_,
                               heap_type_);
    return MapUpdater::ReconfigureExistingProperty(
        isolate, map, descriptor_, PropertyKind::kData, attributes_,
        PropertyConstness::kConst);
  }
};


struct ReconfigureAsAccessorPropertyOperator {
  InternalIndex descriptor_;
  PropertyAttributes attributes_;

  ReconfigureAsAccessorPropertyOperator(int descriptor,
                                        PropertyAttributes attributes = NONE)
      : descriptor_(descriptor), attributes_(attributes) {}

  Handle<Map> DoTransition(Isolate* isolate, Expectations* expectations,
                           Handle<Map> map) {
    expectations->SetAccessorField(descriptor_.as_int());
    return MapUpdater::ReconfigureExistingProperty(
        isolate, map, descriptor_, PropertyKind::kAccessor, attributes_,
        PropertyConstness::kConst);
  }
};

// Checks that field generalization happened.
struct FieldGeneralizationChecker {
  int descriptor_;
  PropertyConstness constness_;
  Representation representation_;
  PropertyAttributes attributes_;
  Handle<FieldType> heap_type_;

  FieldGeneralizationChecker(int descriptor, PropertyConstness constness,
                             Representation representation,
                             Handle<FieldType> heap_type,
                             PropertyAttributes attributes = NONE)
      : descriptor_(descriptor),
        constness_(constness),
        representation_(representation),
        attributes_(attributes),
        heap_type_(heap_type) {}

  void Check(Isolate* isolate, Expectations* expectations, Handle<Map> map1,
             DirectHandle<Map> map2) {
    CHECK(!map2->is_deprecated());

    CHECK(map1->is_deprecated());
    CHECK_NE(*map1, *map2);
    DirectHandle<Map> updated_map = Map::Update(isolate, map1);
    CHECK_EQ(*map2, *updated_map);
    CheckMigrationTarget(isolate, *map1, *updated_map);

    expectations->SetDataField(descriptor_, attributes_, constness_,
                               representation_, heap_type_);
    CHECK(expectations->Check(*map2));
  }
};


// Checks that existing transition was taken as is.
struct SameMapChecker {
  void Check(Isolate* isolate, Expectations* expectations,
             DirectHandle<Map> map1, DirectHandle<Map> map2) {
    CHECK(!map2->is_deprecated());
    CHECK_EQ(*map1, *map2);
    CHECK(expectations->Check(*map2));
  }
};


// Checks that both |map1| and |map2| should stays non-deprecated, this is
// the case when property kind is change.
struct PropertyKindReconfigurationChecker {
  void Check(Expectations* expectations, DirectHandle<Map> map1,
             DirectHandle<Map> map2) {
    CHECK(!map1->is_deprecated());
    CHECK(!map2->is_deprecated());
    CHECK_NE(*map1, *map2);
    CHECK(expectations->Check(*map2));
  }
};


// This test transitions to various property types under different
// circumstances.
// Plan:
// 1) create a |map| with p0..p3 properties.
// 2) create |map1| by adding "p4" to |map0|.
// 3) create |map2| by transition to "p4" from |map0|.
//
//                       + - p4B: |map2|
//                       |
//  {} - p0 - p1 - pA - p3: |map|
//                       |
//                       + - p4A: |map1|
//
// where "p4A" and "p4B" differ only in the attributes.
//
template <typename TransitionOp1, typename TransitionOp2, typename Checker>
static void TestTransitionTo(TransitionOp1* transition_op1,
                             TransitionOp2* transition_op2, Checker* checker) {
  Isolate* isolate = CcTest::i_isolate();
  Handle<FieldType> any_type = FieldType::Any(isolate);

  Expectations expectations(isolate);

  // Create a map, add required properties to it and initialize expectations.
  Handle<Map> initial_map = Map::Create(isolate, 0);
  Handle<Map> map = initial_map;
  for (int i = 0; i < kPropCount - 1; i++) {
    map = expectations.AddDataField(map, NONE, PropertyConstness::kMutable,
                                    Representation::Smi(), any_type);
  }
  CHECK(expectations.Check(*map));

  Expectations expectations1 = expectations;
  Handle<Map> map1 = transition_op1->DoTransition(&expectations1, map);
  CHECK(expectations1.Check(*map1));

  Expectations expectations2 = expectations;
  Handle<Map> map2 = transition_op2->DoTransition(&expectations2, map);

  // Let the test customization do the check.
  checker->Check(isolate, &expectations2, map1, map2);
}

TEST(TransitionDataFieldToDataField) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);

  Handle<Object> value1 = handle(Smi::zero(), isolate);
  TransitionToDataFieldOperator transition_op1(
      PropertyConstness::kMutable, Representation::Smi(), any_type, value1);

  Handle<Object> value2 = isolate->factory()->NewHeapNumber(0);
  TransitionToDataFieldOperator transition_op2(
      PropertyConstness::kMutable, Representation::Double(), any_type, value2);

  FieldGeneralizationChecker checker(kPropCount - 1,
                                     PropertyConstness::kMutable,
                                     Representation::Double(), any_type);
  TestTransitionTo(&transition_op1, &transition_op2, &checker);
}

TEST(TransitionDataConstantToSameDataConstant) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  Handle<JSFunction> js_func =
      factory->NewFunctionForTesting(factory->empty_string());
  TransitionToDataConstantOperator transition_op(js_func);

  SameMapChecker checker;
  TestTransitionTo(&transition_op, &transition_op, &checker);
}


TEST(TransitionDataConstantToAnotherDataConstant) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  Handle<String> name = factory->empty_string();
  Handle<Map> sloppy_map =
      Map::CopyInitialMap(isolate, isolate->sloppy_function_map());
  Handle<SharedFunctionInfo> info = factory->NewSharedFunctionInfoForBuiltin(
      name, Builtin::kIllegal, 0, kDontAdapt);
  CHECK(sloppy_map->is_stable());

  Handle<JSFunction> js_func1 =
      Factory::JSFunctionBuilder{isolate, info, isolate->native_context()}
          .set_map(sloppy_map)
          .Build();
  TransitionToDataConstantOperator transition_op1(js_func1);

  Handle<JSFunction> js_func2 =
      Factory::JSFunctionBuilder{isolate, info, isolate->native_context()}
          .set_map(sloppy_map)
          .Build();
  TransitionToDataConstantOperator transition_op2(js_func2);

  SameMapChecker checker;
  TestTransitionTo(&transition_op1, &transition_op2, &checker);
}


TEST(TransitionDataConstantToDataField) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  Handle<FieldType> any_type = FieldType::Any(isolate);

  Handle<JSFunction> js_func1 =
      factory->NewFunctionForTesting(factory->empty_string());
  TransitionToDataConstantOperator transition_op1(js_func1);

  Handle<Object> value2 = isolate->factory()->NewHeapNumber(0);
  TransitionToDataFieldOperator transition_op2(
      PropertyConstness::kMutable, Representation::Tagged(), any_type, value2);

  SameMapChecker checker;
  TestTransitionTo(&transition_op1, &transition_op2, &checker);
}


TEST(TransitionAccessorConstantToSameAccessorConstant) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  Handle<AccessorPair> pair = CreateAccessorPair(true, true);
  TransitionToAccessorConstantOperator transition_op(pair);

  SameMapChecker checker;
  TestTransitionTo(&transition_op, &transition_op, &checker);
}

// TODO(ishell): add this test once IS_ACCESSOR_FIELD_SUPPORTED is supported.
// TEST(TransitionAccessorConstantToAnotherAccessorConstant)

TEST(HoleyHeapNumber) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  auto mhn = isolate->factory()->NewHeapNumberWithHoleNaN();
  CHECK_EQ(kHoleNanInt64, mhn->value_as_bits());

  mhn = isolate->factory()->NewHeapNumber(0.0);
  CHECK_EQ(uint64_t{0}, mhn->value_as_bits());

  mhn->set_value_as_bits(kHoleNanInt64);
  CHECK_EQ(kHoleNanInt64, mhn->value_as_bits());

  // Ensure that new storage for uninitialized value or mutable heap number
  // with uninitialized sentinel (kHoleNanInt64) is a mutable heap number
  // with uninitialized sentinel.
  DirectHandle<Object> obj =
      Object::NewStorageFor(isolate, isolate->factory()->uninitialized_value(),
                            Representation::Double());
  CHECK(IsHeapNumber(*obj));
  CHECK_EQ(kHoleNanInt64, Cast<HeapNumber>(*obj)->value_as_bits());

  obj = Object::NewStorageFor(isolate, mhn, Representation::Double());
  CHECK(IsHeapNumber(*obj));
  CHECK_EQ(kHoleNanInt64, Cast<HeapNumber>(*obj)->value_as_bits());
}

namespace {

te
```