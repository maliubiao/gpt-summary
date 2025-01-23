Response:
My thought process to analyze the provided C++ code snippet and fulfill the request goes like this:

1. **Understand the Goal:** The user wants to understand the functionality of the C++ code, specifically `v8/test/cctest/test-inobject-slack-tracking.cc`. The request also includes specific points like checking for Torque source, relating it to JavaScript, providing examples, and inferring functionality.

2. **Initial Code Scan:** I quickly scanned the code for keywords and patterns:
    * `#include`:  Indicates C++ code.
    * `namespace v8::internal::test_inobject_slack_tracking`:  Clearly points to the area of focus: in-object slack tracking within V8's internal testing framework.
    * `TEST(...)`:  These are Google Test macros, confirming this is a test file.
    * `JSObject`, `Map`, `Handle`, `Factory`: These are V8 internal data structures and classes related to JavaScript objects and their representation.
    * `CompileRun`, `RunI`:  Suggests execution of JavaScript code within the tests.
    * `GetFieldValue`, `GetDoubleFieldValue`:  Methods for accessing object properties.
    * `IsObjectShrinkable`: A key function indicating the core concept being tested.
    * Class definitions (`class A`, `class B`): Shows tests involving classes and inheritance.
    * Object literals (`{ ... }`):  Tests involving JavaScript object literal creation.

3. **Identify the Core Functionality:** The presence of `IsObjectShrinkable` and the numerous tests manipulating `JSObject` instances strongly suggest the core functionality is **testing the in-object slack tracking mechanism in V8**. This mechanism optimizes object memory usage by initially allocating extra space (slack) for properties and then shrinking the object if not all the slack is used.

4. **Break Down the Tests:**  I examined individual `TEST(...)` blocks to understand specific scenarios being tested:
    * `JSObjectBasic`: Basic object creation and property assignment.
    * `JSObjectComplex`: More complex object creation with conditional property assignment.
    * `JSGeneratorObjectBasic`: Tests with generator functions.
    * `SubclassBasic...`: Tests involving class inheritance.
    * `ObjectLiteralPropertyBackingStoreSize`: Focuses on how object literals allocate space.
    * `SlowModeSubclass`: Tests scenarios where objects transition to "dictionary mode" (less optimized).
    * `SubclassBuiltin`: Tests subclassing built-in JavaScript objects.

5. **Relate to JavaScript:** Since the tests are about JavaScript object behavior within V8, I considered how these concepts manifest in JavaScript:
    * Object creation (`new A()`, `{ a: 1 }`).
    * Property assignment (`obj.a = 42`).
    * Class inheritance (`class B extends A`).
    * The internal optimization of object size is generally transparent to JavaScript developers but affects performance.

6. **Infer Code Logic and Provide Examples:**  Based on the test names and the operations performed, I inferred the logic being tested. For example, the `JSObjectBasic` test checks if an object is initially shrinkable and becomes non-shrinkable after more instances are created. This directly relates to how V8's slack tracking is intended to work. I then crafted JavaScript examples to illustrate these concepts.

7. **Identify Potential User Errors:**  I thought about how developers might unintentionally trigger or be affected by the underlying mechanisms being tested. Common errors related to object properties and performance came to mind, such as:
    * Adding too many properties to objects dynamically.
    * Creating many objects with slightly different structures, which could hinder optimization.

8. **Address Specific Request Points:**
    * **Torque Source:** The file extension `.cc` indicates it's a C++ source file, not a Torque file (`.tq`).
    * **JavaScript Relation and Examples:** I provided clear JavaScript examples illustrating the concepts being tested in the C++ code.
    * **Code Logic Inference:** I explained the core logic of in-object slack tracking.
    * **Assumptions and Outputs:** I made reasonable assumptions about the test setup and described the expected outcomes (e.g., object being initially shrinkable).
    * **Common Programming Errors:**  I provided examples of common mistakes related to object properties.

9. **Structure the Output:**  I organized the information clearly, addressing each point of the user's request systematically. I used headings and bullet points for better readability.

10. **Refine and Review:** I reread my analysis to ensure accuracy, clarity, and completeness, double-checking that it addressed all aspects of the user's request. For example, I made sure to emphasize that the slack tracking is an *optimization* and generally transparent to JavaScript code.
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include <sstream>
#include <utility>

#include "src/api/api-inl.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/objects-inl.h"
#include "test/cctest/cctest.h"

namespace v8 {
namespace internal {
namespace test_inobject_slack_tracking {

static const int kMaxInobjectProperties = JSObject::kMaxInObjectProperties;

template <typename T>
static Handle<T> OpenHandle(v8::Local<v8::Value> value) {
  Handle<Object> obj = v8::Utils::OpenHandle(*value);
  return Cast<T>(obj);
}

static inline v8::Local<v8::Value> Run(v8::Local<v8::Script> script) {
  v8::Local<v8::Value> result;
  if (script->Run(CcTest::isolate()->GetCurrentContext()).ToLocal(&result)) {
    return result;
  }
  return v8::Local<v8::Value>();
}



template <typename T = Object>
Handle<T> GetLexical(const char* name) {
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  Handle<String> str_name = factory->InternalizeUtf8String(name);
  DirectHandle<ScriptContextTable> script_contexts(
      isolate->native_context()->script_context_table(), isolate);

  VariableLookupResult lookup_result;
  if (script_contexts->Lookup(str_name, &lookup_result)) {
    Tagged<Context> script_context =
        script_contexts->get(lookup_result.context_index);
    Handle<Object> result(script_context->get(lookup_result.slot_index),
                          isolate);
    return Cast<T>(result);
  }
  return Handle<T>();
}

template <typename T = Object>
Handle<T> GetLexical(const std::string& name) {
  return GetLexical<T>(name.c_str());
}

template <typename T>
static inline Handle<T> RunI(v8::Local<v8::Script> script) {
  return OpenHandle<T>(Run(script));
}

template <typename T>
static inline Handle<T> CompileRunI(const char* script) {
  return OpenHandle<T>(CompileRun(script));
}

static Tagged<Object> GetFieldValue(Tagged<JSObject> obj, int property_index) {
  FieldIndex index = FieldIndex::ForPropertyIndex(obj->map(), property_index);
  return obj->RawFastPropertyAt(index);
}

static double GetDoubleFieldValue(Tagged<JSObject> obj,
                                  FieldIndex field_index) {
  Tagged<Object> value = obj->RawFastPropertyAt(field_index);
  if (IsHeapNumber(value)) {
    return Cast<HeapNumber>(value)->value();
  } else {
    return Object::NumberValue(value);
  }
}

static double GetDoubleFieldValue(Tagged<JSObject> obj, int property_index) {
  FieldIndex index = FieldIndex::ForPropertyIndex(obj->map(), property_index);
  return GetDoubleFieldValue(obj, index);
}

bool IsObjectShrinkable(Tagged<JSObject> obj) {
  DirectHandle<Map> filler_map =
      CcTest::i_isolate()->factory()->one_pointer_filler_map();

  int inobject_properties = obj->map()->GetInObjectProperties();
  int unused = obj->map()->UnusedPropertyFields();
  if (unused == 0) return false;

  Address packed_filler = MapWord::FromMap(*filler_map).ptr();
  for (int i = inobject_properties - unused; i < inobject_properties; i++) {
    if (packed_filler != GetFieldValue(obj, i).ptr()) {
      return false;
    }
  }
  return true;
}

TEST(JSObjectBasic) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  const char* source =
      "function A() {"
      "  this.a = 42;"
      "  this.d = 4.2;"
      "  this.o = this;"
      "}";
  CompileRun(source);

  DirectHandle<JSFunction> func = GetGlobal<JSFunction>("A");

  // Zero instances were created so far.
  CHECK(!func->has_initial_map());

  v8::Local<v8::Script> new_A_script = v8_compile("new A();");

  DirectHandle<JSObject> obj = RunI<JSObject>(new_A_script);

  CHECK(func->has_initial_map());
  DirectHandle<Map> initial_map(func->initial_map(), func->GetIsolate());

  // One instance created.
  CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
           initial_map->construction_counter());
  CHECK(initial_map->IsInobjectSlackTrackingInProgress());

  // There must be at least some slack.
  CHECK_LT(5, obj->map()->GetInObjectProperties());
  CHECK_EQ(Smi::FromInt(42), GetFieldValue(*obj, 0));
  CHECK_EQ(4.2, GetDoubleFieldValue(*obj, 1));
  CHECK_EQ(*obj, GetFieldValue(*obj, 2));
  CHECK(IsObjectShrinkable(*obj));

  // Create several objects to complete the tracking.
  for (int i = 1; i < Map::kGenerousAllocationCount; i++) {
    CHECK(initial_map->IsInobjectSlackTrackingInProgress());
    DirectHandle<JSObject> tmp = RunI<JSObject>(new_A_script);
    CHECK_EQ(initial_map->IsInobjectSlackTrackingInProgress(),
             IsObjectShrinkable(*tmp));
  }
  CHECK(!initial_map->IsInobjectSlackTrackingInProgress());
  CHECK(!IsObjectShrinkable(*obj));

  // No slack left.
  CHECK_EQ(3, obj->map()->GetInObjectProperties());
}

TEST(JSObjectBasicNoInlineNew) {
  v8_flags.inline_new = false;
  TestJSObjectBasic();
}

TEST(JSObjectComplex) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  const char* source =
      "function A(n) {"
      "  if (n > 0) this.a = 42;"
      "  if (n > 1) this.d = 4.2;"
      "  if (n > 2) this.o1 = this;"
      "  if (n > 3) this.o2 = this;"
      "  if (n > 4) this.o3 = this;"
      "  if (n > 5) this.o4 = this;"
      "}";
  CompileRun(source);

  DirectHandle<JSFunction> func = GetGlobal<JSFunction>("A");

  // Zero instances were created so far.
  CHECK(!func->has_initial_map());

  DirectHandle<JSObject> obj1 = CompileRunI<JSObject>("new A(1);");
  DirectHandle<JSObject> obj3 = CompileRunI<JSObject>("new A(3);");
  DirectHandle<JSObject> obj5 = CompileRunI<JSObject>("new A(5);");

  CHECK(func->has_initial_map());
  DirectHandle<Map> initial_map(func->initial_map(), func->GetIsolate());

  // Three instances created.
  CHECK_EQ(Map::kSlackTrackingCounterStart - 3,
           initial_map->construction_counter());
  CHECK(initial_map->IsInobjectSlackTrackingInProgress());

  // There must be at least some slack.
  CHECK_LT(5, obj3->map()->GetInObjectProperties());
  CHECK_EQ(Smi::FromInt(42), GetFieldValue(*obj3, 0));
  CHECK_EQ(4.2, GetDoubleFieldValue(*obj3, 1));
  CHECK_EQ(*obj3, GetFieldValue(*obj3, 2));
  CHECK(IsObjectShrinkable(*obj1));
  CHECK(IsObjectShrinkable(*obj3));
  CHECK(IsObjectShrinkable(*obj5));

  // Create several objects to complete the tracking.
  for (int i = 3; i < Map::kGenerousAllocationCount; i++) {
    CHECK(initial_map->IsInobjectSlackTrackingInProgress());
    CompileRun("new A(3);");
  }
  CHECK(!initial_map->IsInobjectSlackTrackingInProgress());

  // obj1 and obj2 stays shrinkable because we don't clear unused fields.
  CHECK(IsObjectShrinkable(*obj1));
  CHECK(IsObjectShrinkable(*obj3));
  CHECK(!IsObjectShrinkable(*obj5));

  CHECK_EQ(5, obj1->map()->GetInObjectProperties());
  CHECK_EQ(4, obj1->map()->UnusedPropertyFields());

  CHECK_EQ(5, obj3->map()->GetInObjectProperties());
  CHECK_EQ(2, obj3->map()->UnusedPropertyFields());

  CHECK_EQ(5, obj5->map()->GetInObjectProperties());
  CHECK_EQ(0, obj5->map()->UnusedPropertyFields());

  // Since slack tracking is complete, the new objects should not be shrinkable.
  obj1 = CompileRunI<JSObject>("new A(1);");
  obj3 = CompileRunI<JSObject>("new A(3);");
  obj5 = CompileRunI<JSObject>("new A(5);");

  CHECK(!IsObjectShrinkable(*obj1));
  CHECK(!IsObjectShrinkable(*obj3));
  CHECK(!IsObjectShrinkable(*obj5));
}

TEST(JSObjectComplexNoInlineNew) {
  v8_flags.inline_new = false;
  TestJSObjectComplex();
}

TEST(JSGeneratorObjectBasic) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  const char* source =
      "function* A() {"
      "  var i = 0;"
      "  while(true) {"
      "    yield i++;"
      "  }"
      "};"
      "function CreateGenerator() {"
      "  var o = A();"
      "  o.a = 42;"
      "  o.d = 4.2;"
      "  o.o = o;"
      "  return o;"
      "}";
  CompileRun(source);

  DirectHandle<JSFunction> func = GetGlobal<JSFunction>("A");

  // Zero instances were created so far.
  CHECK(!func->has_initial_map());

  v8::Local<v8::Script> new_A_script = v8_compile("CreateGenerator();");

  DirectHandle<JSObject> obj = RunI<JSObject>(new_A_script);

  CHECK(func->has_initial_map());
  DirectHandle<Map> initial_map(func->initial_map(), func->GetIsolate());

  // One instance created.
  CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
           initial_map->construction_counter());
  CHECK(initial_map->IsInobjectSlackTrackingInProgress());

  // There must be at least some slack.
  CHECK_LT(5, obj->map()->GetInObjectProperties());
  CHECK_EQ(Smi::FromInt(42), GetFieldValue(*obj, 0));
  CHECK_EQ(4.2, GetDoubleFieldValue(*obj, 1));
  CHECK_EQ(*obj, GetFieldValue(*obj, 2));
  CHECK(IsObjectShrinkable(*obj));

  // Create several objects to complete the tracking.
  for (int i = 1; i < Map::kGenerousAllocationCount; i++) {
    CHECK(initial_map->IsInobjectSlackTrackingInProgress());
    DirectHandle<JSObject> tmp = RunI<JSObject>(new_A_script);
    CHECK_EQ(initial_map->IsInobjectSlackTrackingInProgress(),
             IsObjectShrinkable(*tmp));
  }
  CHECK(!initial_map->IsInobjectSlackTrackingInProgress());
  CHECK(!IsObjectShrinkable(*obj));

  // No slack left.
  CHECK_EQ(3, obj->map()->GetInObjectProperties());
}

TEST(JSGeneratorObjectBasicNoInlineNew) {
  v8_flags.inline_new = false;
  TestJSGeneratorObjectBasic();
}

TEST(SubclassBasicNoBaseClassInstances) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  // Check that base class' and subclass' slack tracking do not interfere with
  // each other.
  // In this test we never create base class instances.

  const char* source =
      "'use strict';"
      "class A {"
      "  constructor(...args) {"
      "    this.aa = 42;"
      "    this.ad = 4.2;"
      "    this.ao = this;"
      "  }"
      "};"
      "class B extends A {"
      "  constructor(...args) {"
      "    super(...args);"
      "    this.ba = 142;"
      "    this.bd = 14.2;"
      "    this.bo = this;"
      "  }"
      "};";
  CompileRun(source);

  DirectHandle<JSFunction> a_func = GetLexical<JSFunction>("A");
  DirectHandle<JSFunction> b_func = GetLexical<JSFunction>("B");

  // Zero instances were created so far.
  CHECK(!a_func->has_initial_map());
  CHECK(!b_func->has_initial_map());

  v8::Local<v8::Script> new_B_script = v8_compile("new B();");

  DirectHandle<JSObject> obj = RunI<JSObject>(new_B_script);

  CHECK(a_func->has_initial_map());
  DirectHandle<Map> a_initial_map(a_func->initial_map(), a_func->GetIsolate());

  CHECK(b_func->has_initial_map());
  DirectHandle<Map> b_initial_map(b_func->initial_map(), a_func->GetIsolate());

  // Zero instances of A created.
  CHECK_EQ(Map::kSlackTrackingCounterStart,
           a_initial_map->construction_counter());
  CHECK(a_initial_map->IsInobjectSlackTrackingInProgress());

  // One instance of B created.
  CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
           b_initial_map->construction_counter());
  CHECK(b_initial_map->IsInobjectSlackTrackingInProgress());

  // There must be at least some slack.
  CHECK_LT(10, obj->map()->GetInObjectProperties());
  CHECK_EQ(Smi::FromInt(42), GetFieldValue(*obj, 0));
  CHECK_EQ(4.2, GetDoubleFieldValue(*obj, 1));
  CHECK_EQ(*obj, GetFieldValue(*obj, 2));
  CHECK_EQ(Smi::FromInt(142), GetFieldValue(*obj, 3));
  CHECK_EQ(14.2, GetDoubleFieldValue(*obj, 4));
  CHECK_EQ(*obj, GetFieldValue(*obj, 5));
  CHECK(IsObjectShrinkable(*obj));

  // Create several subclass instances to complete the tracking.
  for (int i = 1; i < Map::kGenerousAllocationCount; i++) {
    CHECK(b_initial_map->IsInobjectSlackTrackingInProgress());
    DirectHandle<JSObject> tmp = RunI<JSObject>(new_B_script);
    CHECK_EQ(b_initial_map->IsInobjectSlackTrackingInProgress(),
             IsObjectShrinkable(*tmp));
  }
  CHECK(!b_initial_map->IsInobjectSlackTrackingInProgress());
  CHECK(!IsObjectShrinkable(*obj));

  // Zero instances of A created.
  CHECK_EQ(Map::kSlackTrackingCounterStart,
           a_initial_map->construction_counter());
  CHECK(a_initial_map->IsInobjectSlackTrackingInProgress());

  // No slack left.
  CHECK_EQ(6, obj->map()->GetInObjectProperties());
}

TEST(SubclassBasicNoBaseClassInstancesNoInlineNew) {
  v8_flags.inline_new = false;
  TestSubclassBasicNoBaseClassInstances();
}

TEST(SubclassBasic) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  // Check that base class' and subclass' slack tracking do not interfere with
  // each other.
  // In this test we first create enough base class instances to complete
  // the slack tracking and then proceed creating subclass instances.

  const char* source =
      "'use strict';"
      "class A {"
      "  constructor(...args) {"
      "    this.aa = 42;"
      "    this.ad = 4.2;"
      "    this.ao = this;"
      "  }"
      "};"
      "class B extends A {"
      "  constructor(...args) {"
      "    super(...args);"
      "    this.ba = 142;"
      "    this.bd = 14.2;"
      "    this.bo = this;"
      "  }"
      "};";
  CompileRun(source);

  DirectHandle<JSFunction> a_func = GetLexical<JSFunction>("A");
  DirectHandle<JSFunction> b_func = GetLexical<JSFunction>("B");

  // Zero instances were created so far.
  CHECK(!a_func->has_initial_map());
  CHECK(!b_func->has_initial_map());

  v8::Local<v8::Script> new_A_script = v8_compile("new A();");
  v8::Local<v8::Script> new_B_script = v8_compile("new B();");

  DirectHandle<JSObject> a_obj = RunI<JSObject>(new_A_script);
  DirectHandle<JSObject> b_obj = RunI<JSObject>(new_B_script);

  CHECK(a_func->has_initial_map());
  DirectHandle<Map> a_initial_map(a_func->initial_map(), a_func->GetIsolate());

  CHECK(b_func->has_initial_map());
  DirectHandle<Map> b_initial_map(b_func->initial_map(), a_func->GetIsolate());

  // One instance of a base class created.
  CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
           a_initial_map->construction_counter());
  CHECK(a_initial_map->IsInobjectSlackTrackingInProgress());

  // One instance of a subclass created.
  CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
           b_initial_map->construction_counter());
  CHECK(b_initial_map->IsInobjectSlackTrackingInProgress());

  // Create several base class instances to complete the tracking.
  for (int i = 1; i < Map::kGenerousAllocationCount; i++) {
    CHECK(a_initial_map->IsInobjectSlackTrackingInProgress());
    DirectHandle<JSObject> tmp = RunI<JSObject>(new_A_script);
    CHECK_EQ(a_initial_map->IsInobjectSlackTrackingInProgress(),
             IsObjectShrinkable(*tmp));
  }
  CHECK(!a_initial_map->IsInobjectSlackTrackingInProgress());
  CHECK(!IsObjectShrinkable(*a_obj));

  // No slack left.
  CHECK_EQ(3, a_obj->map()->GetInObjectProperties());

  // There must be at least some slack.
  CHECK_LT(10, b_obj->map()->GetInObjectProperties());
  CHECK_EQ(Smi::FromInt(42), GetFieldValue(*b_obj, 0));
  CHECK_EQ(4.2, GetDoubleFieldValue(*b_obj, 1));
  CHECK_EQ(*b_obj, GetFieldValue(*b_obj, 2));
  CHECK_EQ(Smi::FromInt(142), GetFieldValue(*b_obj, 3));
  CHECK_EQ(14.2, GetDoubleFieldValue(*b_obj, 4));
  CHECK_EQ(*b_obj, GetFieldValue(*b_obj, 5));
  CHECK(IsObjectShrinkable(*b_obj));

  // Create several subclass instances to complete the tracking.
  for (int i = 1; i < Map::kGenerousAllocationCount; i++) {
    CHECK(b_initial_map->IsInobjectSlackTrackingInProgress());
    DirectHandle<JSObject> tmp = RunI<JSObject>(new_B_script);
    CHECK_EQ(b_initial_map->IsInobjectSlackTrackingInProgress(),
             IsObjectShrinkable(*tmp));
  }
  CHECK(!b_initial_map->IsInobjectSlackTrackingInProgress());
  CHECK(!IsObjectShrinkable(*b_obj));

  // No slack left.
  CHECK_EQ(6, b_obj->map()->GetInObjectProperties());
}

TEST(SubclassBasicNoInlineNew) {
  v8_flags.inline_new = false;
  TestSubclassBasic();
}

// Creates class hierarchy of length matching the |hierarchy_desc| length and
// with the number of fields at i'th level equal to |hierarchy_desc[i]|.
static void CreateClassHierarchy(const std::vector<int>& hierarchy_desc) {
  std::ostringstream os;
  os << "'use strict';\n\n";

  int n = static_cast<int>(hierarchy_desc.size());
  for (int cur_class = 0; cur_class < n; cur_class++) {
    os << "class A" << cur_class;
    if (cur_class > 0) {
      os << " extends A" << (cur_class - 1);
    }
    os << " {\n"
          "  constructor(...args) {\n";
    if (cur_class > 0) {
      os << "    super(...args);\n";
    }
    int fields_count = hierarchy_desc[cur_class];
    for (int k = 0; k < fields_count; k++) {
      os << "    this.f" << cur_class << "_" << k << " = " << k << ";\n";
    }
    os << "  }\n"
          "};\n\n";
  }
  CompileRun(os.str().c_str());
}

static std::string GetClassName(int class_index) {
  std::ostringstream os;
  os << "A" << class_index;
  return os.str();
}

static v8::Local<v8::Script> GetNewObjectScript(const std::string& class_name) {
  std::ostringstream os;
  os << "new " << class_name << "();";
  return v8_compile(os.str().c_str());
}

// Test that in-object slack tracking works as expected for first |n| classes
// in the hierarchy.
// This test works only for if the total property count is less than maximum
// in-object properties count.
static void TestClassHierarchy(const std::vector<int>& hierarchy_desc, int n) {
  int fields_count = 0;
  for (int cur_class = 0; cur_class < n; cur_class++) {
    std::string class_name = GetClassName(cur_class);
    int fields_count_at_current_level = hierarchy_desc[cur_class];
    fields_count += fields_count_at_current_level;

    // This test is not suitable for in-object properties count overflow case.
    CHECK_LT(fields_count, kMaxInobjectProperties);

    // Create |class_name| objects and check slack tracking.
    v8::Local<v8::Script> new_script = GetNewObjectScript(class_name);

    DirectHandle<JSFunction> func = GetLexical<JSFunction>(class_name);

    DirectHandle<JSObject> obj = RunI<JSObject>(new_script);

    CHECK(func->has_initial_map());
    DirectHandle<Map> initial_map(func->initial_map(), func->GetIsolate());

    // If the object is slow-mode already, bail out.
    if (obj->map()->is_dictionary_map()) continue;

    // There must be at least some slack.
    CHECK_LT(fields_count, obj->map()->GetInObjectProperties());

    // One instance was created.
    CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
             initial_map->construction_counter());
    CHECK(initial_map->IsInobjectSlackTrackingInProgress());

    // Create several instances to complete the tracking.
    for (int i = 1; i < Map::kGenerousAllocationCount; i++) {
      CHECK(initial_map->IsInobjectSlackTrackingInProgress());
      DirectHandle<JSObject> tmp = RunI<JSObject>(new_script);
      CHECK_EQ(initial_map->IsInobjectSlackTrackingInProgress(),
               IsObjectShrinkable(*tmp));
      if (!initial_map->IsInobjectSlackTrackingInProgress()) {
        // Turbofan can force completion of in-object slack tracking.
        break;
      }
      CHECK_EQ(Map::kSlackTrackingCounterStart - i - 1,
               initial_map->construction_counter());
    }
    CHECK(!initial_map->IsInobjectSlackTrackingInProgress());
    CHECK(!IsObjectShrinkable(*obj));

    // No slack left.
    CHECK_EQ(fields_count, obj->map()->GetInObjectProperties());
  }
}

static void TestSubclassChain(const std::vector<int>& hierarchy_desc) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  CreateClassHierarchy(hierarchy_desc);
  TestClassHierarchy(hierarchy_desc, static_cast<int>(hierarchy_desc.size()));
}

TEST(Subclasses) {
  std::vector<int> hierarchy_desc;
  hierarchy_desc.push_back(50);
  hierarchy_desc.push_back(128);
  TestSubclassChain(hierarchy_desc);
}

TEST(LongSubclassChain1) {
  std::vector<int> hierarchy_desc;
  for (int i = 0; i < 7; i++) {
    hierarchy_desc.push_back(i * 10);
  }
  TestSubclassChain(hierarchy_desc);
}

TEST(LongSubclassChain2) {
  std::vector<int> hierarchy_desc;
  hierarchy_desc.push_back(10);
  for (int i = 0; i < 42; i++) {
    hierarchy_desc.push_back(0);
  }
  hierarchy_desc.push_back(230);
  TestSubclassChain(hierarchy_desc);
}

TEST(LongSubclassChain3) {
  std::vector<int> hierarchy_desc;
  for (int i = 0; i < 42; i++) {
    hierarchy_desc.push_back(5);
  }
  TestSubclassChain(hierarchy_desc);
}

TEST(InobjectPropetiesCountOverflowInSubclass) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  std::vector<int> hierarchy_desc;
  const int kNoOverflowCount = 5;
  for (int i = 0; i < kNoOverflowCount; i++) {
    hierarchy_desc.push_back(50);
  }
  // In this class we are going to have properties in the backing store.
  hierarchy_desc.push_back(100);

  CreateClassHierarchy(hierarchy_desc);

  // For the last class in the hierarchy we need different checks.
  {
    int cur_class = kNoOverflowCount;
    std::string class_name = GetClassName(cur_class);

    // Create |class_name| objects and check slack tracking.
    v8::Local<v8::Script> new_script = GetNewObjectScript(class_name);

    DirectHandle<JSFunction> func = GetLexical<JSFunction>(class_name);

    DirectHandle<JSObject> obj = RunI<JSObject>(new_script);

    CHECK(func->has_initial_map());
    DirectHandle<Map> initial_map(func->initial_map(), func->GetIsolate());

    // There must be no slack left.
    CHECK_EQ(JSObject::kMaxInstanceSize, obj->map()->instance_size());
    CHECK_EQ(kMaxInobjectProperties, obj->map()->GetInObjectProperties());

    // One instance was created.
    CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
             initial_map->construction_counter());
    CHECK(initial_map->IsInobjectSlackTrackingInProgress());

    // Create several instances to complete the tracking.
    for (int i = 1
### 提示词
```
这是目录为v8/test/cctest/test-inobject-slack-tracking.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-inobject-slack-tracking.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include <sstream>
#include <utility>

#include "src/api/api-inl.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/objects-inl.h"
#include "test/cctest/cctest.h"

namespace v8 {
namespace internal {
namespace test_inobject_slack_tracking {

static const int kMaxInobjectProperties = JSObject::kMaxInObjectProperties;

template <typename T>
static Handle<T> OpenHandle(v8::Local<v8::Value> value) {
  Handle<Object> obj = v8::Utils::OpenHandle(*value);
  return Cast<T>(obj);
}


static inline v8::Local<v8::Value> Run(v8::Local<v8::Script> script) {
  v8::Local<v8::Value> result;
  if (script->Run(CcTest::isolate()->GetCurrentContext()).ToLocal(&result)) {
    return result;
  }
  return v8::Local<v8::Value>();
}



template <typename T = Object>
Handle<T> GetLexical(const char* name) {
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  Handle<String> str_name = factory->InternalizeUtf8String(name);
  DirectHandle<ScriptContextTable> script_contexts(
      isolate->native_context()->script_context_table(), isolate);

  VariableLookupResult lookup_result;
  if (script_contexts->Lookup(str_name, &lookup_result)) {
    Tagged<Context> script_context =
        script_contexts->get(lookup_result.context_index);
    Handle<Object> result(script_context->get(lookup_result.slot_index),
                          isolate);
    return Cast<T>(result);
  }
  return Handle<T>();
}


template <typename T = Object>
Handle<T> GetLexical(const std::string& name) {
  return GetLexical<T>(name.c_str());
}

template <typename T>
static inline Handle<T> RunI(v8::Local<v8::Script> script) {
  return OpenHandle<T>(Run(script));
}

template <typename T>
static inline Handle<T> CompileRunI(const char* script) {
  return OpenHandle<T>(CompileRun(script));
}

static Tagged<Object> GetFieldValue(Tagged<JSObject> obj, int property_index) {
  FieldIndex index = FieldIndex::ForPropertyIndex(obj->map(), property_index);
  return obj->RawFastPropertyAt(index);
}

static double GetDoubleFieldValue(Tagged<JSObject> obj,
                                  FieldIndex field_index) {
  Tagged<Object> value = obj->RawFastPropertyAt(field_index);
  if (IsHeapNumber(value)) {
    return Cast<HeapNumber>(value)->value();
  } else {
    return Object::NumberValue(value);
  }
}

static double GetDoubleFieldValue(Tagged<JSObject> obj, int property_index) {
  FieldIndex index = FieldIndex::ForPropertyIndex(obj->map(), property_index);
  return GetDoubleFieldValue(obj, index);
}

bool IsObjectShrinkable(Tagged<JSObject> obj) {
  DirectHandle<Map> filler_map =
      CcTest::i_isolate()->factory()->one_pointer_filler_map();

  int inobject_properties = obj->map()->GetInObjectProperties();
  int unused = obj->map()->UnusedPropertyFields();
  if (unused == 0) return false;

  Address packed_filler = MapWord::FromMap(*filler_map).ptr();
  for (int i = inobject_properties - unused; i < inobject_properties; i++) {
    if (packed_filler != GetFieldValue(obj, i).ptr()) {
      return false;
    }
  }
  return true;
}

TEST(JSObjectBasic) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  const char* source =
      "function A() {"
      "  this.a = 42;"
      "  this.d = 4.2;"
      "  this.o = this;"
      "}";
  CompileRun(source);

  DirectHandle<JSFunction> func = GetGlobal<JSFunction>("A");

  // Zero instances were created so far.
  CHECK(!func->has_initial_map());

  v8::Local<v8::Script> new_A_script = v8_compile("new A();");

  DirectHandle<JSObject> obj = RunI<JSObject>(new_A_script);

  CHECK(func->has_initial_map());
  DirectHandle<Map> initial_map(func->initial_map(), func->GetIsolate());

  // One instance created.
  CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
           initial_map->construction_counter());
  CHECK(initial_map->IsInobjectSlackTrackingInProgress());

  // There must be at least some slack.
  CHECK_LT(5, obj->map()->GetInObjectProperties());
  CHECK_EQ(Smi::FromInt(42), GetFieldValue(*obj, 0));
  CHECK_EQ(4.2, GetDoubleFieldValue(*obj, 1));
  CHECK_EQ(*obj, GetFieldValue(*obj, 2));
  CHECK(IsObjectShrinkable(*obj));

  // Create several objects to complete the tracking.
  for (int i = 1; i < Map::kGenerousAllocationCount; i++) {
    CHECK(initial_map->IsInobjectSlackTrackingInProgress());
    DirectHandle<JSObject> tmp = RunI<JSObject>(new_A_script);
    CHECK_EQ(initial_map->IsInobjectSlackTrackingInProgress(),
             IsObjectShrinkable(*tmp));
  }
  CHECK(!initial_map->IsInobjectSlackTrackingInProgress());
  CHECK(!IsObjectShrinkable(*obj));

  // No slack left.
  CHECK_EQ(3, obj->map()->GetInObjectProperties());
}


TEST(JSObjectBasicNoInlineNew) {
  v8_flags.inline_new = false;
  TestJSObjectBasic();
}


TEST(JSObjectComplex) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  const char* source =
      "function A(n) {"
      "  if (n > 0) this.a = 42;"
      "  if (n > 1) this.d = 4.2;"
      "  if (n > 2) this.o1 = this;"
      "  if (n > 3) this.o2 = this;"
      "  if (n > 4) this.o3 = this;"
      "  if (n > 5) this.o4 = this;"
      "}";
  CompileRun(source);

  DirectHandle<JSFunction> func = GetGlobal<JSFunction>("A");

  // Zero instances were created so far.
  CHECK(!func->has_initial_map());

  DirectHandle<JSObject> obj1 = CompileRunI<JSObject>("new A(1);");
  DirectHandle<JSObject> obj3 = CompileRunI<JSObject>("new A(3);");
  DirectHandle<JSObject> obj5 = CompileRunI<JSObject>("new A(5);");

  CHECK(func->has_initial_map());
  DirectHandle<Map> initial_map(func->initial_map(), func->GetIsolate());

  // Three instances created.
  CHECK_EQ(Map::kSlackTrackingCounterStart - 3,
           initial_map->construction_counter());
  CHECK(initial_map->IsInobjectSlackTrackingInProgress());

  // There must be at least some slack.
  CHECK_LT(5, obj3->map()->GetInObjectProperties());
  CHECK_EQ(Smi::FromInt(42), GetFieldValue(*obj3, 0));
  CHECK_EQ(4.2, GetDoubleFieldValue(*obj3, 1));
  CHECK_EQ(*obj3, GetFieldValue(*obj3, 2));
  CHECK(IsObjectShrinkable(*obj1));
  CHECK(IsObjectShrinkable(*obj3));
  CHECK(IsObjectShrinkable(*obj5));

  // Create several objects to complete the tracking.
  for (int i = 3; i < Map::kGenerousAllocationCount; i++) {
    CHECK(initial_map->IsInobjectSlackTrackingInProgress());
    CompileRun("new A(3);");
  }
  CHECK(!initial_map->IsInobjectSlackTrackingInProgress());

  // obj1 and obj2 stays shrinkable because we don't clear unused fields.
  CHECK(IsObjectShrinkable(*obj1));
  CHECK(IsObjectShrinkable(*obj3));
  CHECK(!IsObjectShrinkable(*obj5));

  CHECK_EQ(5, obj1->map()->GetInObjectProperties());
  CHECK_EQ(4, obj1->map()->UnusedPropertyFields());

  CHECK_EQ(5, obj3->map()->GetInObjectProperties());
  CHECK_EQ(2, obj3->map()->UnusedPropertyFields());

  CHECK_EQ(5, obj5->map()->GetInObjectProperties());
  CHECK_EQ(0, obj5->map()->UnusedPropertyFields());

  // Since slack tracking is complete, the new objects should not be shrinkable.
  obj1 = CompileRunI<JSObject>("new A(1);");
  obj3 = CompileRunI<JSObject>("new A(3);");
  obj5 = CompileRunI<JSObject>("new A(5);");

  CHECK(!IsObjectShrinkable(*obj1));
  CHECK(!IsObjectShrinkable(*obj3));
  CHECK(!IsObjectShrinkable(*obj5));
}


TEST(JSObjectComplexNoInlineNew) {
  v8_flags.inline_new = false;
  TestJSObjectComplex();
}


TEST(JSGeneratorObjectBasic) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  const char* source =
      "function* A() {"
      "  var i = 0;"
      "  while(true) {"
      "    yield i++;"
      "  }"
      "};"
      "function CreateGenerator() {"
      "  var o = A();"
      "  o.a = 42;"
      "  o.d = 4.2;"
      "  o.o = o;"
      "  return o;"
      "}";
  CompileRun(source);

  DirectHandle<JSFunction> func = GetGlobal<JSFunction>("A");

  // Zero instances were created so far.
  CHECK(!func->has_initial_map());

  v8::Local<v8::Script> new_A_script = v8_compile("CreateGenerator();");

  DirectHandle<JSObject> obj = RunI<JSObject>(new_A_script);

  CHECK(func->has_initial_map());
  DirectHandle<Map> initial_map(func->initial_map(), func->GetIsolate());

  // One instance created.
  CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
           initial_map->construction_counter());
  CHECK(initial_map->IsInobjectSlackTrackingInProgress());

  // There must be at least some slack.
  CHECK_LT(5, obj->map()->GetInObjectProperties());
  CHECK_EQ(Smi::FromInt(42), GetFieldValue(*obj, 0));
  CHECK_EQ(4.2, GetDoubleFieldValue(*obj, 1));
  CHECK_EQ(*obj, GetFieldValue(*obj, 2));
  CHECK(IsObjectShrinkable(*obj));

  // Create several objects to complete the tracking.
  for (int i = 1; i < Map::kGenerousAllocationCount; i++) {
    CHECK(initial_map->IsInobjectSlackTrackingInProgress());
    DirectHandle<JSObject> tmp = RunI<JSObject>(new_A_script);
    CHECK_EQ(initial_map->IsInobjectSlackTrackingInProgress(),
             IsObjectShrinkable(*tmp));
  }
  CHECK(!initial_map->IsInobjectSlackTrackingInProgress());
  CHECK(!IsObjectShrinkable(*obj));

  // No slack left.
  CHECK_EQ(3, obj->map()->GetInObjectProperties());
}


TEST(JSGeneratorObjectBasicNoInlineNew) {
  v8_flags.inline_new = false;
  TestJSGeneratorObjectBasic();
}


TEST(SubclassBasicNoBaseClassInstances) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  // Check that base class' and subclass' slack tracking do not interfere with
  // each other.
  // In this test we never create base class instances.

  const char* source =
      "'use strict';"
      "class A {"
      "  constructor(...args) {"
      "    this.aa = 42;"
      "    this.ad = 4.2;"
      "    this.ao = this;"
      "  }"
      "};"
      "class B extends A {"
      "  constructor(...args) {"
      "    super(...args);"
      "    this.ba = 142;"
      "    this.bd = 14.2;"
      "    this.bo = this;"
      "  }"
      "};";
  CompileRun(source);

  DirectHandle<JSFunction> a_func = GetLexical<JSFunction>("A");
  DirectHandle<JSFunction> b_func = GetLexical<JSFunction>("B");

  // Zero instances were created so far.
  CHECK(!a_func->has_initial_map());
  CHECK(!b_func->has_initial_map());

  v8::Local<v8::Script> new_B_script = v8_compile("new B();");

  DirectHandle<JSObject> obj = RunI<JSObject>(new_B_script);

  CHECK(a_func->has_initial_map());
  DirectHandle<Map> a_initial_map(a_func->initial_map(), a_func->GetIsolate());

  CHECK(b_func->has_initial_map());
  DirectHandle<Map> b_initial_map(b_func->initial_map(), a_func->GetIsolate());

  // Zero instances of A created.
  CHECK_EQ(Map::kSlackTrackingCounterStart,
           a_initial_map->construction_counter());
  CHECK(a_initial_map->IsInobjectSlackTrackingInProgress());

  // One instance of B created.
  CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
           b_initial_map->construction_counter());
  CHECK(b_initial_map->IsInobjectSlackTrackingInProgress());

  // There must be at least some slack.
  CHECK_LT(10, obj->map()->GetInObjectProperties());
  CHECK_EQ(Smi::FromInt(42), GetFieldValue(*obj, 0));
  CHECK_EQ(4.2, GetDoubleFieldValue(*obj, 1));
  CHECK_EQ(*obj, GetFieldValue(*obj, 2));
  CHECK_EQ(Smi::FromInt(142), GetFieldValue(*obj, 3));
  CHECK_EQ(14.2, GetDoubleFieldValue(*obj, 4));
  CHECK_EQ(*obj, GetFieldValue(*obj, 5));
  CHECK(IsObjectShrinkable(*obj));

  // Create several subclass instances to complete the tracking.
  for (int i = 1; i < Map::kGenerousAllocationCount; i++) {
    CHECK(b_initial_map->IsInobjectSlackTrackingInProgress());
    DirectHandle<JSObject> tmp = RunI<JSObject>(new_B_script);
    CHECK_EQ(b_initial_map->IsInobjectSlackTrackingInProgress(),
             IsObjectShrinkable(*tmp));
  }
  CHECK(!b_initial_map->IsInobjectSlackTrackingInProgress());
  CHECK(!IsObjectShrinkable(*obj));

  // Zero instances of A created.
  CHECK_EQ(Map::kSlackTrackingCounterStart,
           a_initial_map->construction_counter());
  CHECK(a_initial_map->IsInobjectSlackTrackingInProgress());

  // No slack left.
  CHECK_EQ(6, obj->map()->GetInObjectProperties());
}


TEST(SubclassBasicNoBaseClassInstancesNoInlineNew) {
  v8_flags.inline_new = false;
  TestSubclassBasicNoBaseClassInstances();
}


TEST(SubclassBasic) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  // Check that base class' and subclass' slack tracking do not interfere with
  // each other.
  // In this test we first create enough base class instances to complete
  // the slack tracking and then proceed creating subclass instances.

  const char* source =
      "'use strict';"
      "class A {"
      "  constructor(...args) {"
      "    this.aa = 42;"
      "    this.ad = 4.2;"
      "    this.ao = this;"
      "  }"
      "};"
      "class B extends A {"
      "  constructor(...args) {"
      "    super(...args);"
      "    this.ba = 142;"
      "    this.bd = 14.2;"
      "    this.bo = this;"
      "  }"
      "};";
  CompileRun(source);

  DirectHandle<JSFunction> a_func = GetLexical<JSFunction>("A");
  DirectHandle<JSFunction> b_func = GetLexical<JSFunction>("B");

  // Zero instances were created so far.
  CHECK(!a_func->has_initial_map());
  CHECK(!b_func->has_initial_map());

  v8::Local<v8::Script> new_A_script = v8_compile("new A();");
  v8::Local<v8::Script> new_B_script = v8_compile("new B();");

  DirectHandle<JSObject> a_obj = RunI<JSObject>(new_A_script);
  DirectHandle<JSObject> b_obj = RunI<JSObject>(new_B_script);

  CHECK(a_func->has_initial_map());
  DirectHandle<Map> a_initial_map(a_func->initial_map(), a_func->GetIsolate());

  CHECK(b_func->has_initial_map());
  DirectHandle<Map> b_initial_map(b_func->initial_map(), a_func->GetIsolate());

  // One instance of a base class created.
  CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
           a_initial_map->construction_counter());
  CHECK(a_initial_map->IsInobjectSlackTrackingInProgress());

  // One instance of a subclass created.
  CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
           b_initial_map->construction_counter());
  CHECK(b_initial_map->IsInobjectSlackTrackingInProgress());

  // Create several base class instances to complete the tracking.
  for (int i = 1; i < Map::kGenerousAllocationCount; i++) {
    CHECK(a_initial_map->IsInobjectSlackTrackingInProgress());
    DirectHandle<JSObject> tmp = RunI<JSObject>(new_A_script);
    CHECK_EQ(a_initial_map->IsInobjectSlackTrackingInProgress(),
             IsObjectShrinkable(*tmp));
  }
  CHECK(!a_initial_map->IsInobjectSlackTrackingInProgress());
  CHECK(!IsObjectShrinkable(*a_obj));

  // No slack left.
  CHECK_EQ(3, a_obj->map()->GetInObjectProperties());

  // There must be at least some slack.
  CHECK_LT(10, b_obj->map()->GetInObjectProperties());
  CHECK_EQ(Smi::FromInt(42), GetFieldValue(*b_obj, 0));
  CHECK_EQ(4.2, GetDoubleFieldValue(*b_obj, 1));
  CHECK_EQ(*b_obj, GetFieldValue(*b_obj, 2));
  CHECK_EQ(Smi::FromInt(142), GetFieldValue(*b_obj, 3));
  CHECK_EQ(14.2, GetDoubleFieldValue(*b_obj, 4));
  CHECK_EQ(*b_obj, GetFieldValue(*b_obj, 5));
  CHECK(IsObjectShrinkable(*b_obj));

  // Create several subclass instances to complete the tracking.
  for (int i = 1; i < Map::kGenerousAllocationCount; i++) {
    CHECK(b_initial_map->IsInobjectSlackTrackingInProgress());
    DirectHandle<JSObject> tmp = RunI<JSObject>(new_B_script);
    CHECK_EQ(b_initial_map->IsInobjectSlackTrackingInProgress(),
             IsObjectShrinkable(*tmp));
  }
  CHECK(!b_initial_map->IsInobjectSlackTrackingInProgress());
  CHECK(!IsObjectShrinkable(*b_obj));

  // No slack left.
  CHECK_EQ(6, b_obj->map()->GetInObjectProperties());
}


TEST(SubclassBasicNoInlineNew) {
  v8_flags.inline_new = false;
  TestSubclassBasic();
}


// Creates class hierarchy of length matching the |hierarchy_desc| length and
// with the number of fields at i'th level equal to |hierarchy_desc[i]|.
static void CreateClassHierarchy(const std::vector<int>& hierarchy_desc) {
  std::ostringstream os;
  os << "'use strict';\n\n";

  int n = static_cast<int>(hierarchy_desc.size());
  for (int cur_class = 0; cur_class < n; cur_class++) {
    os << "class A" << cur_class;
    if (cur_class > 0) {
      os << " extends A" << (cur_class - 1);
    }
    os << " {\n"
          "  constructor(...args) {\n";
    if (cur_class > 0) {
      os << "    super(...args);\n";
    }
    int fields_count = hierarchy_desc[cur_class];
    for (int k = 0; k < fields_count; k++) {
      os << "    this.f" << cur_class << "_" << k << " = " << k << ";\n";
    }
    os << "  }\n"
          "};\n\n";
  }
  CompileRun(os.str().c_str());
}


static std::string GetClassName(int class_index) {
  std::ostringstream os;
  os << "A" << class_index;
  return os.str();
}


static v8::Local<v8::Script> GetNewObjectScript(const std::string& class_name) {
  std::ostringstream os;
  os << "new " << class_name << "();";
  return v8_compile(os.str().c_str());
}


// Test that in-object slack tracking works as expected for first |n| classes
// in the hierarchy.
// This test works only for if the total property count is less than maximum
// in-object properties count.
static void TestClassHierarchy(const std::vector<int>& hierarchy_desc, int n) {
  int fields_count = 0;
  for (int cur_class = 0; cur_class < n; cur_class++) {
    std::string class_name = GetClassName(cur_class);
    int fields_count_at_current_level = hierarchy_desc[cur_class];
    fields_count += fields_count_at_current_level;

    // This test is not suitable for in-object properties count overflow case.
    CHECK_LT(fields_count, kMaxInobjectProperties);

    // Create |class_name| objects and check slack tracking.
    v8::Local<v8::Script> new_script = GetNewObjectScript(class_name);

    DirectHandle<JSFunction> func = GetLexical<JSFunction>(class_name);

    DirectHandle<JSObject> obj = RunI<JSObject>(new_script);

    CHECK(func->has_initial_map());
    DirectHandle<Map> initial_map(func->initial_map(), func->GetIsolate());

    // If the object is slow-mode already, bail out.
    if (obj->map()->is_dictionary_map()) continue;

    // There must be at least some slack.
    CHECK_LT(fields_count, obj->map()->GetInObjectProperties());

    // One instance was created.
    CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
             initial_map->construction_counter());
    CHECK(initial_map->IsInobjectSlackTrackingInProgress());

    // Create several instances to complete the tracking.
    for (int i = 1; i < Map::kGenerousAllocationCount; i++) {
      CHECK(initial_map->IsInobjectSlackTrackingInProgress());
      DirectHandle<JSObject> tmp = RunI<JSObject>(new_script);
      CHECK_EQ(initial_map->IsInobjectSlackTrackingInProgress(),
               IsObjectShrinkable(*tmp));
      if (!initial_map->IsInobjectSlackTrackingInProgress()) {
        // Turbofan can force completion of in-object slack tracking.
        break;
      }
      CHECK_EQ(Map::kSlackTrackingCounterStart - i - 1,
               initial_map->construction_counter());
    }
    CHECK(!initial_map->IsInobjectSlackTrackingInProgress());
    CHECK(!IsObjectShrinkable(*obj));

    // No slack left.
    CHECK_EQ(fields_count, obj->map()->GetInObjectProperties());
  }
}


static void TestSubclassChain(const std::vector<int>& hierarchy_desc) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  CreateClassHierarchy(hierarchy_desc);
  TestClassHierarchy(hierarchy_desc, static_cast<int>(hierarchy_desc.size()));
}

TEST(Subclasses) {
  std::vector<int> hierarchy_desc;
  hierarchy_desc.push_back(50);
  hierarchy_desc.push_back(128);
  TestSubclassChain(hierarchy_desc);
}

TEST(LongSubclassChain1) {
  std::vector<int> hierarchy_desc;
  for (int i = 0; i < 7; i++) {
    hierarchy_desc.push_back(i * 10);
  }
  TestSubclassChain(hierarchy_desc);
}


TEST(LongSubclassChain2) {
  std::vector<int> hierarchy_desc;
  hierarchy_desc.push_back(10);
  for (int i = 0; i < 42; i++) {
    hierarchy_desc.push_back(0);
  }
  hierarchy_desc.push_back(230);
  TestSubclassChain(hierarchy_desc);
}


TEST(LongSubclassChain3) {
  std::vector<int> hierarchy_desc;
  for (int i = 0; i < 42; i++) {
    hierarchy_desc.push_back(5);
  }
  TestSubclassChain(hierarchy_desc);
}


TEST(InobjectPropetiesCountOverflowInSubclass) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  std::vector<int> hierarchy_desc;
  const int kNoOverflowCount = 5;
  for (int i = 0; i < kNoOverflowCount; i++) {
    hierarchy_desc.push_back(50);
  }
  // In this class we are going to have properties in the backing store.
  hierarchy_desc.push_back(100);

  CreateClassHierarchy(hierarchy_desc);

  // For the last class in the hierarchy we need different checks.
  {
    int cur_class = kNoOverflowCount;
    std::string class_name = GetClassName(cur_class);

    // Create |class_name| objects and check slack tracking.
    v8::Local<v8::Script> new_script = GetNewObjectScript(class_name);

    DirectHandle<JSFunction> func = GetLexical<JSFunction>(class_name);

    DirectHandle<JSObject> obj = RunI<JSObject>(new_script);

    CHECK(func->has_initial_map());
    DirectHandle<Map> initial_map(func->initial_map(), func->GetIsolate());

    // There must be no slack left.
    CHECK_EQ(JSObject::kMaxInstanceSize, obj->map()->instance_size());
    CHECK_EQ(kMaxInobjectProperties, obj->map()->GetInObjectProperties());

    // One instance was created.
    CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
             initial_map->construction_counter());
    CHECK(initial_map->IsInobjectSlackTrackingInProgress());

    // Create several instances to complete the tracking.
    for (int i = 1; i < Map::kGenerousAllocationCount; i++) {
      CHECK(initial_map->IsInobjectSlackTrackingInProgress());
      DirectHandle<JSObject> tmp = RunI<JSObject>(new_script);
      CHECK(!IsObjectShrinkable(*tmp));
    }
    CHECK(!initial_map->IsInobjectSlackTrackingInProgress());
    CHECK(!IsObjectShrinkable(*obj));

    // No slack left.
    CHECK_EQ(kMaxInobjectProperties, obj->map()->GetInObjectProperties());
  }

  // The other classes in the hierarchy are not affected.
  TestClassHierarchy(hierarchy_desc, kNoOverflowCount);
}

static void CheckExpectedProperties(int expected, std::ostringstream& os) {
  DirectHandle<HeapObject> obj = Cast<HeapObject>(
      v8::Utils::OpenDirectHandle(*CompileRun(os.str().c_str())));
  CHECK_EQ(expected, obj->map()->GetInObjectProperties());
}

TEST(ObjectLiteralPropertyBackingStoreSize) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;

  std::ostringstream os;

  // An index key does not require space in the property backing store.
  os << "(function() {\n"
        "  function f() {\n"
        "    var o = {\n"
        "      '-1': 42,\n"  // Allocate for non-index key.
        "      1: 42,\n"     // Do not allocate for index key.
        "      '2': 42\n"    // Do not allocate for index key.
        "    };\n"
        "    return o;\n"
        "  }\n"
        "\n"
        "  return f();\n"
        "} )();";
  CheckExpectedProperties(1, os);

  // Avoid over-/under-allocation for computed property names.
  os << "(function() {\n"
        "  'use strict';\n"
        "  function f(x) {\n"
        "    var o = {\n"
        "      1: 42,\n"    // Do not allocate for index key.
        "      '2': 42,\n"  // Do not allocate for index key.
        "      [x]: 42,\n"  // Allocate for property with computed name.
        "      3: 42,\n"    // Do not allocate for index key.
        "      '4': 42\n"   // Do not allocate for index key.
        "    };\n"
        "    return o;\n"
        "  }\n"
        "\n"
        "  var x = 'hello'\n"
        "\n"
        "  return f(x);\n"
        "} )();";
  CheckExpectedProperties(1, os);

  // Conversion to index key.
  os << "(function() {\n"
        "  function f(x) {\n"
        "    var o = {\n"
        "      1: 42,\n"       // Do not allocate for index key.
        "      '2': 42,\n"     // Do not allocate for index key.
        "      [x]: 42,\n"     // Allocate for property with computed name.
        "      3: 42,\n"       // Do not allocate for index key.
        "      get 12() {}\n"  // Do not allocate for index key.
        "    };\n"
        "    return o;\n"
        "  }\n"
        "\n"
        "  var x = 'hello'\n"
        "\n"
        "  return f(x);\n"
        "} )();";
  CheckExpectedProperties(1, os);

  os << "(function() {\n"
        "  function f() {\n"
        "    var o = {};\n"
        "    return o;\n"
        "  }\n"
        "\n"
        "  return f();\n"
        "} )();";
  // Empty objects have slack for 4 properties.
  CheckExpectedProperties(4, os);

  os << "(function() {\n"
        "  function f(x) {\n"
        "    var o = {\n"
        "      a: 42,\n"    // Allocate for constant property.
        "      [x]: 42,\n"  // Allocate for property with computed name.
        "      b: 42\n"     // Allocate for constant property.
        "    };\n"
        "    return o;\n"
        "  }\n"
        "\n"
        "  var x = 'hello'\n"
        "\n"
        "  return f(x);\n"
        "} )();";
  CheckExpectedProperties(3, os);

  os << "(function() {\n"
        "  function f(x) {\n"
        "    var o = {\n"
        "      a: 42,\n"          // Allocate for constant property.
        "      __proto__: 42,\n"  // Do not allocate for __proto__.
        "      [x]: 42\n"         // Allocate for property with computed name.
        "    };\n"
        "    return o;\n"
        "  }\n"
        "\n"
        "  var x = 'hello'\n"
        "\n"
        "  return f(x);\n"
        "} )();";
  // __proto__ is not allocated in the backing store.
  CheckExpectedProperties(2, os);

  os << "(function() {\n"
        "  function f(x) {\n"
        "    var o = {\n"
        "      a: 42,\n"         // Allocate for constant property.
        "      [x]: 42,\n"       // Allocate for property with computed name.
        "      __proto__: 42\n"  // Do not allocate for __proto__.
        "    };\n"
        "    return o;\n"
        "  }\n"
        "\n"
        "  var x = 'hello'\n"
        "\n"
        "  return f(x);\n"
        "} )();";
  CheckExpectedProperties(2, os);
}

TEST(SlowModeSubclass) {
  if (v8_flags.stress_concurrent_allocation) return;

  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  std::vector<int> hierarchy_desc;
  const int kNoOverflowCount = 5;
  for (int i = 0; i < kNoOverflowCount; i++) {
    hierarchy_desc.push_back(50);
  }
  // This class should go dictionary mode.
  hierarchy_desc.push_back(1000);

  CreateClassHierarchy(hierarchy_desc);

  // For the last class in the hierarchy we need different checks.
  {
    int cur_class = kNoOverflowCount;
    std::string class_name = GetClassName(cur_class);

    // Create |class_name| objects and check slack tracking.
    v8::Local<v8::Script> new_script = GetNewObjectScript(class_name);

    DirectHandle<JSFunction> func = GetLexical<JSFunction>(class_name);

    DirectHandle<JSObject> obj = RunI<JSObject>(new_script);

    CHECK(func->has_initial_map());
    DirectHandle<Map> initial_map(func->initial_map(), func->GetIsolate());

    // Object should go dictionary mode.
    CHECK_EQ(JSObject::kHeaderSize, obj->map()->instance_size());
    CHECK(obj->map()->is_dictionary_map());

    // One instance was created.
    CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
             initial_map->construction_counter());
    CHECK(initial_map->IsInobjectSlackTrackingInProgress());

    // Create several instances to complete the tracking.
    for (int i = 1; i < Map::kGenerousAllocationCount; i++) {
      CHECK(initial_map->IsInobjectSlackTrackingInProgress());
      DirectHandle<JSObject> tmp = RunI<JSObject>(new_script);
      CHECK(!IsObjectShrinkable(*tmp));
    }
    CHECK(!initial_map->IsInobjectSlackTrackingInProgress());
    CHECK(!IsObjectShrinkable(*obj));

    // Object should stay in dictionary mode.
    CHECK_EQ(JSObject::kHeaderSize, obj->map()->instance_size());
    CHECK(obj->map()->is_dictionary_map());
  }

  // The other classes in the hierarchy are not affected.
  TestClassHierarchy(hierarchy_desc, kNoOverflowCount);
}


static void TestSubclassBuiltin(const char* subclass_name,
                                InstanceType instance_type,
                                const char* builtin_name,
                                const char* ctor_arguments = "",
                                int builtin_properties_count = 0) {
  {
    std::ostringstream os;
    os << "'use strict';\n"
          "class "
       << subclass_name << " extends " << builtin_name
       << " {\n"
          "  constructor(...args) {\n"
          "    super(...args);\n"
          "    this.a = 42;\n"
          "    this.d = 4.2;\n"
          "    this.o = this;\n"
          "  }\n"
          "};\n";
    CompileRun(os.str().c_str());
  }

  DirectHandle<JSFunction> func = GetLexical<JSFunction>(subclass_name);

  // Zero instances were created so far.
  CHECK(!func->has_initial_map());

  v8::Local<v8::Script> new_script;
  {
    std::ostringstream os;
    os << "new " << subclass_name << "(" << ctor_arguments << ");";
    new_script = v8_compile(os.str().c_str());
  }

  RunI<JSObject>(new_script);

  CHECK(func->has_initial_map());
  DirectHandle<Map> initial_map(func->initial_map(), func->GetIsolate());

  CHECK_EQ(instance_type, initial_map->instance_type());

  // One instance of a subclass created.
  CHECK_EQ(Map::kSlackTrackingCounterStart - 1,
           initial_map->construction_counter());
  CHECK(initial_map->IsInobjectSlackTrackingInProgress());

  // Create two instances in order to ensure that |obj|.o is a data field
  // in case of Function subclassing.
  DirectHandle<JSObject> obj = RunI<JSObject>(new_script);

  // Two instances of a subclass created.
  CHECK_EQ(Map::kSlackTrackingCounterStart - 2,
           initial_map->construction_counter());
  CHECK(initial_map->IsInobjectSlackTrackingInProgress());

  // There must be at least some slack.
  CHECK_LT(builtin_properties_count + 5, obj->map()->GetInObjectProperties());
  CHECK_EQ(Smi::FromInt(42), GetFieldValue(*obj, builtin_properties_count + 0));
  CHECK_EQ(4.2, GetDoubleFieldValue(*obj, builtin_properties_count + 1));
  CHECK_EQ(*obj, GetFieldValue(*obj, builtin_properties_count + 2));
  CHECK(IsObjectShrinkable(*obj));

  // Create several subclass instances to complete the tracking.
  for (int i = 2; i < Map::kGenerousAllocationCount; i++) {
    CHECK(initial_map->IsInobjectSlackTrackingInProgress());
    DirectHandle<JSObject> tmp = RunI<JSObject>(new_script);
    CHECK_EQ(initial_map->IsInobjectSlackTrackingInProgress(),
             IsObjectShrinkable(*tmp));
  }
  CHECK(!initial_map->IsInobjectSlackTrackingInProgress());
  CHECK(!IsObjectShrinkable(*obj));

  // No slack left.
  CHECK_EQ(builtin_properties_count + 3, obj->map()->GetInObjectProperties());

  CHECK_EQ(instance_type, obj->map()->instance_type());
}


TEST(SubclassObjectBuiltin) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  TestSubclassBuiltin("A1", JS_OBJECT_TYPE, "Object", "true");
  TestSubclassBuiltin("A2", JS_OBJECT_TYPE, "Object", "42");
  TestSubclassBuiltin("A3", JS_OBJECT_TYPE, "Object", "'some string'");
}


TEST(SubclassObjectBuiltinNoInlineNew) {
  v8_flags.inline_new = false;
  TestSubclassObjectBuiltin();
}


TEST(SubclassFunctionBuiltin) {
  // Avoid possible completion of in-object slack tracking.
  v8_flags.always_turbofan = false;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  TestSubclassBuiltin("A1", JS_FUNCTION_TYPE, "Function", "'return 153;'");
  TestSubclassBuiltin("A2", JS_FUNCTION_TYPE, "Function", "'this.a = 44;'");
}


TEST(SubclassFunctionBuiltinNoInlineNew) {
  v8_flags.inline_
```