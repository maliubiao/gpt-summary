Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/cctest/test-api.cc`.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Purpose:** The code consists of several `TEST` macros. This immediately signals that the primary function of this code is *testing* V8's API. Each `TEST` likely focuses on a specific aspect of the API.

2. **Analyze Individual Tests:**  Go through each `TEST` block and try to understand what it's doing. Look for:
    * **Setup:** How are V8 isolates and contexts being created and managed? (`v8::Isolate::Scope`, `v8::HandleScope`, `v8::Context::New`, `v8::Context::Scope`)
    * **Execution:** What V8 API calls are being made? (`CompileRun`, `v->IsNumber()`, `v->NumberValue()`, `isolate->SetFatalErrorHandler`, `String.prototype.charAt = ...`, `Number.prototype.toString = ...`, `delete cell`, `object.SetWrapperClassId`, `v8::RegExp::New`, `regexp->Exec`, `object->GetPrototype`, `tmpl->SetHandler`, `Object::defineProperty`, `object->GetCreationContext`, `function->bind`, `object->HasOwnProperty`, `context->AllowCodeGenerationFromStrings`, `isolate->SetModifyCodeGenerationFromStringsCallback`)
    * **Assertions:** What checks are being performed? (`CHECK`, `CHECK_EQ`, `ExpectString`, `ExpectBoolean`, `ExpectTrue`, `CHECK(try_catch.HasCaught())`) These assertions tell you what the expected behavior is.

3. **Group Tests by Functionality:**  As you analyze individual tests, you'll notice patterns and common themes. Group the tests based on the V8 API features they are exercising. For example:
    * Basic code execution (`CompileRun`) and value checking.
    * Isolate management (secondary thread initialization, fatal handlers, etc.).
    * Multiple contexts and how they interact (prototype modifications).
    * Object property handling (`delete`, `WrapperClassId`).
    * Regular expressions (`v8::RegExp`).
    * Object equality (`Equals`).
    * Interceptors for properties (getters, enumerators, queries).
    * `defineProperty`.
    * Creation contexts of objects and functions.
    * `hasOwnProperty`.
    * Code generation from strings (allowing/disallowing `eval` and `Function`).

4. **Address Specific Questions in the Prompt:** Once you have a good understanding of the tests, address the specific points raised in the prompt:

    * **Functionality Listing:** Summarize the grouped functionalities in a clear list.
    * **`.tq` Check:**  The code is `.cc`, so it's C++, not Torque. State this explicitly.
    * **JavaScript Examples:** For tests related to JavaScript functionality (like prototype modification or `hasOwnProperty`), provide corresponding JavaScript examples to illustrate the concepts.
    * **Logic Reasoning (Assumptions and Outputs):** For tests involving code execution, consider simple input strings for `CompileRun` and predict the output based on the code.
    * **Common Programming Errors:** Identify tests that demonstrate potential errors developers might make when interacting with V8, such as incorrect context usage or unexpected behavior with prototypes.
    * **Overall Functionality (Summary):**  Provide a concise summary of the purpose of the code, emphasizing that it's a test suite for V8's C++ API.

5. **Structure the Answer:** Organize the information logically using headings and bullet points to make it easy to read and understand.

6. **Review and Refine:**  Read through your answer to ensure accuracy, clarity, and completeness. Check that you've addressed all aspects of the prompt. For instance, double-check if all JavaScript examples are correct and illustrative. Make sure assumptions and outputs are clearly stated and logically follow from the code.

**Self-Correction Example During the Process:**

Initially, I might just list all the `TEST` names. However, upon closer inspection, I'd realize that many tests relate to similar concepts. For example, several tests involve multiple contexts. This would prompt me to group these tests under a "Multiple Contexts" category, which provides a more organized and insightful understanding than just listing individual test names. Similarly,  recognizing the pattern of `CompileRun` and `CHECK` statements leads to understanding the basic code execution and assertion mechanism used in the tests.
```cpp
late::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);
    Local<Value> v = CompileRun("2");
    CHECK(v->IsNumber());
    CHECK_EQ(2, static_cast<int>(v->NumberValue(context).FromJust()));
  }
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);
    Local<Value> v = CompileRun("22");
    CHECK(v->IsNumber());
    CHECK_EQ(22, static_cast<int>(v->NumberValue(context).FromJust()));
  }
  isolate->Dispose();
}

class InitDefaultIsolateThread : public v8::base::Thread {
 public:
  enum TestCase {
    SetFatalHandler,
    SetCounterFunction,
    SetCreateHistogramFunction,
    SetAddHistogramSampleFunction
  };

  explicit InitDefaultIsolateThread(TestCase testCase)
      : Thread(Options("InitDefaultIsolateThread")),
        testCase_(testCase),
        result_(false) {}

  void Run() override {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    isolate->Enter();
    switch (testCase_) {
      case SetFatalHandler:
        isolate->SetFatalErrorHandler(nullptr);
        break;

      case SetCounterFunction:
        CcTest::isolate()->SetCounterFunction(nullptr);
        break;

      case SetCreateHistogramFunction:
        CcTest::isolate()->SetCreateHistogramFunction(nullptr);
        break;

      case SetAddHistogramSampleFunction:
        CcTest::isolate()->SetAddHistogramSampleFunction(nullptr);
        break;
    }
    isolate->Exit();
    isolate->Dispose();
    result_ = true;
  }

  bool result() { return result_; }

 private:
  TestCase testCase_;
  bool result_;
};

static void InitializeTestHelper(InitDefaultIsolateThread::TestCase testCase) {
  InitDefaultIsolateThread thread(testCase);
  CHECK(thread.Start());
  thread.Join();
  CHECK(thread.result());
}

TEST(InitializeDefaultIsolateOnSecondaryThread_FatalHandler) {
  InitializeTestHelper(InitDefaultIsolateThread::SetFatalHandler);
}

TEST(InitializeDefaultIsolateOnSecondaryThread_CounterFunction) {
  InitializeTestHelper(InitDefaultIsolateThread::SetCounterFunction);
}

TEST(InitializeDefaultIsolateOnSecondaryThread_CreateHistogramFunction) {
  InitializeTestHelper(InitDefaultIsolateThread::SetCreateHistogramFunction);
}

TEST(InitializeDefaultIsolateOnSecondaryThread_AddHistogramSampleFunction) {
  InitializeTestHelper(InitDefaultIsolateThread::SetAddHistogramSampleFunction);
}

TEST(StringCheckMultipleContexts) {
  const char* code =
      "(function() { return \"a\".charAt(0); })()";

  {
    // Run the code twice in the first context to initialize the call IC.
    LocalContext context1;
    v8::HandleScope scope(context1->GetIsolate());
    ExpectString(code, "a");
    ExpectString(code, "a");
  }

  {
    // Change the String.prototype in the second context and check
    // that the right function gets called.
    LocalContext context2;
    v8::HandleScope scope(context2->GetIsolate());
    CompileRun("String.prototype.charAt = function() { return \"not a\"; }");
    ExpectString(code, "not a");
  }
}

TEST(NumberCheckMultipleContexts) {
  const char* code =
      "(function() { return (42).toString(); })()";

  {
    // Run the code twice in the first context to initialize the call IC.
    LocalContext context1;
    v8::HandleScope scope(context1->GetIsolate());
    ExpectString(code, "42");
    ExpectString(code, "42");
  }

  {
    // Change the Number.prototype in the second context and check
    // that the right function gets called.
    LocalContext context2;
    v8::HandleScope scope(context2->GetIsolate());
    CompileRun("Number.prototype.toString = function() { return \"not 42\"; }");
    ExpectString(code, "not 42");
  }
}

TEST(BooleanCheckMultipleContexts) {
  const char* code =
      "(function() { return true.toString(); })()";

  {
    // Run the code twice in the first context to initialize the call IC.
    LocalContext context1;
    v8::HandleScope scope(context1->GetIsolate());
    ExpectString(code, "true");
    ExpectString(code, "true");
  }

  {
    // Change the Boolean.prototype in the second context and check
    // that the right function gets called.
    LocalContext context2;
    v8::HandleScope scope(context2->GetIsolate());
    CompileRun("Boolean.prototype.toString = function() { return \"\"; }");
    ExpectString(code, "");
  }
}

TEST(DontDeleteCellLoadIC) {
  const char* function_code =
      "function readCell() { while (true) { return cell; } }";

  {
    // Run the code twice in the first context to initialize the load
    // IC for a don't delete cell.
    LocalContext context1;
    v8::HandleScope scope(context1->GetIsolate());
    CompileRun("var cell = \"first\";");
    ExpectBoolean("delete cell", false);
    CompileRun(function_code);
    ExpectString("readCell()", "first");
    ExpectString("readCell()", "first");
  }

  {
    // Use a deletable cell in the second context.
    LocalContext context2;
    v8::HandleScope scope(context2->GetIsolate());
    CompileRun("cell = \"second\";");
    CompileRun(function_code);
    ExpectString("readCell()", "second");
    ExpectBoolean("delete cell", true);
    ExpectString("(function() {"
                 "  try {"
                 "    return readCell();"
                 "  } catch(e) {"
                 "    return e.toString();"
                 "  }"
                 "})()",
                 "ReferenceError: cell is not defined");
    CompileRun("cell = \"new_second\";");
    i::heap::InvokeMajorGC(CcTest::heap());
    ExpectString("readCell()", "new_second");
    ExpectString("readCell()", "new_second");
  }
}

TEST(WrapperClassId) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Persistent<v8::Object> object(isolate, v8::Object::New(isolate));
  CHECK_EQ(0, object.WrapperClassId());
  object.SetWrapperClassId(65535);
  CHECK_EQ(65535, object.WrapperClassId());
  object.Reset();
}

TEST(RegExp) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  v8::Local<v8::RegExp> re =
      v8::RegExp::New(context.local(), v8_str("foo"), v8::RegExp::kNone)
          .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("foo")).FromJust());
  CHECK_EQ(v8::RegExp::kNone, re->GetFlags());

  re = v8::RegExp::New(context.local(), v8_str("foo/bar"), v8::RegExp::kNone)
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(
      re->GetSource()->Equals(context.local(), v8_str("foo\\/bar")).FromJust());
  CHECK_EQ(v8::RegExp::kNone, re->GetFlags());

  re = v8::RegExp::New(context.local(), v8_str("bar"),
                       static_cast<v8::RegExp::Flags>(v8::RegExp::kIgnoreCase |
                                                      v8::RegExp::kGlobal))
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("bar")).FromJust());
  CHECK_EQ(v8::RegExp::kIgnoreCase | v8::RegExp::kGlobal,
           static_cast<int>(re->GetFlags()));

  re = v8::RegExp::New(context.local(), v8_str("baz"),
                       static_cast<v8::RegExp::Flags>(v8::RegExp::kIgnoreCase |
                                                      v8::RegExp::kMultiline))
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("baz")).FromJust());
  CHECK_EQ(v8::RegExp::kIgnoreCase | v8::RegExp::kMultiline,
           static_cast<int>(re->GetFlags()));

  re = v8::RegExp::New(context.local(), v8_str("baz"),
                       static_cast<v8::RegExp::Flags>(v8::RegExp::kUnicode |
                                                      v8::RegExp::kSticky))
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("baz")).FromJust());
  CHECK_EQ(v8::RegExp::kUnicode | v8::RegExp::kSticky,
           static_cast<int>(re->GetFlags()));

  re = CompileRun("/quux/").As<v8::RegExp>();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("quux")).FromJust());
  CHECK_EQ(v8::RegExp::kNone, re->GetFlags());

  re = CompileRun("RegExp('qu/ux')").As<v8::RegExp>();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("qu\\/ux")).FromJust());
  CHECK_EQ(v8::RegExp::kNone, re->GetFlags());

  re = CompileRun("/quux/gm").As<v8::RegExp>();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("quux")).FromJust());
  CHECK_EQ(v8::RegExp::kGlobal | v8::RegExp::kMultiline,
           static_cast<int>(re->GetFlags()));

  // Override the RegExp constructor and check the API constructor
  // still works.
  CompileRun("RegExp = function() {}");

  re = v8::RegExp::New(context.local(), v8_str("foobar"), v8::RegExp::kNone)
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("foobar")).FromJust());
  CHECK_EQ(v8::RegExp::kNone, re->GetFlags());

  re = v8::RegExp::New(context.local(), v8_str("foobarbaz"),
                       static_cast<v8::RegExp::Flags>(v8::RegExp::kIgnoreCase |
                                                      v8::RegExp::kMultiline))
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(
      re->GetSource()->Equals(context.local(), v8_str("foobarbaz")).FromJust());
  CHECK_EQ(v8::RegExp::kIgnoreCase | v8::RegExp::kMultiline,
           static_cast<int>(re->GetFlags()));

  CHECK(context->Global()->Set(context.local(), v8_str("re"), re).FromJust());
  ExpectTrue("re.test('FoobarbaZ')");

  // RegExps are objects on which you can set properties.
  re->Set(context.local(), v8_str("property"),
          v8::Integer::New(context->GetIsolate(), 32))
      .FromJust();
  v8::Local<v8::Value> value(CompileRun("re.property"));
  CHECK_EQ(32, value->Int32Value(context.local()).FromJust());

  {
    v8::TryCatch try_catch(context->GetIsolate());
    CHECK(v8::RegExp::New(context.local(), v8_str("foo["), v8::RegExp::kNone)
              .IsEmpty());
    CHECK(try_catch.HasCaught());
    CHECK(context->Global()
              ->Set(context.local(), v8_str("ex"), try_catch.Exception())
              .FromJust());
    ExpectTrue("ex instanceof SyntaxError");
  }

  // RegExp::Exec.
  {
    v8::Local<v8::RegExp> regexp =
        v8::RegExp::New(context.local(), v8_str("a.c"), {}).ToLocalChecked();
    v8::Local<v8::Object> result0 =
        regexp->Exec(context.local(), v8_str("abc")).ToLocalChecked();
    CHECK(result0->IsArray());
    v8::Local<v8::Object> result1 =
        regexp->Exec(context.local(), v8_str("abd")).ToLocalChecked();
    CHECK(result1->IsNull());
  }
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
START_ALLOW_USE_DEPRECATED()

THREADED_TEST(Equals) {
  LocalContext localContext;
  v8::HandleScope handleScope(localContext->GetIsolate());

  v8::Local<v8::Object> globalProxy = localContext->Global();
  v8::Local<Value> global = globalProxy->GetPrototype();

  CHECK(global->StrictEquals(global));
  CHECK(!global->StrictEquals(globalProxy));
  CHECK(!globalProxy->StrictEquals(global));
  CHECK(globalProxy->StrictEquals(globalProxy));

  CHECK(global->Equals(localContext.local(), global).FromJust());
  CHECK(!global->Equals(localContext.local(), globalProxy).FromJust());
  CHECK(!globalProxy->Equals(localContext.local(), global).FromJust());
  CHECK(globalProxy->Equals(localContext.local(), globalProxy).FromJust());
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
END_ALLOW_USE_DEPRECATED()

namespace {
v8::Intercepted Getter(v8::Local<v8::Name> property,
                       const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_str("42!"));
  return v8::Intercepted::kYes;
}

void Enumerator(const v8::PropertyCallbackInfo<v8::Array>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::Local<v8::Array> result = v8::Array::New(info.GetIsolate());
  result->Set(info.GetIsolate()->GetCurrentContext(), 0,
              v8_str("universalAnswer"))
      .FromJust();
  info.GetReturnValue().Set(result);
}
}  // namespace

TEST(NamedEnumeratorAndForIn) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  v8::Context::Scope context_scope(context.local());

  v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);
  tmpl->SetHandler(v8::NamedPropertyHandlerConfiguration(
      Getter, nullptr, nullptr, nullptr, Enumerator));
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o"),
                  tmpl->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  v8::Local<v8::Array> result = v8::Local<v8::Array>::Cast(
      CompileRun("var result = []; for (var k in o) result.push(k); result"));
  CHECK_EQ(1u, result->Length());
  CHECK(v8_str("universalAnswer")
            ->Equals(context.local(),
                     result->Get(context.local(), 0).ToLocalChecked())
            .FromJust());
}

TEST(DefinePropertyPostDetach) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::Local<v8::Object> proxy = context->Global();
  v8::Local<v8::Function> define_property =
      CompileRun(
          "(function() {"
          "  Object.defineProperty("
          "    this,"
          "    1,"
          "    { configurable: true, enumerable: true, value: 3 });"
          "})")
          .As<Function>();
  context->DetachGlobal();
  CHECK(define_property->Call(context.local(), proxy, 0, nullptr).IsEmpty());
}

static void InstallContextId(v8::Local<Context> context, int id) {
  Context::Scope scope(context);
  CHECK(CompileRun("Object.prototype")
            .As<Object>()
            ->Set(context, v8_str("context_id"),
                  v8::Integer::New(context->GetIsolate(), id))
            .FromJust());
}

static void CheckContextId(v8::Local<Object> object, int expected) {
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  CHECK_EQ(expected, object->Get(context, v8_str("context_id"))
                         .ToLocalChecked()
                         ->Int32Value(context)
                         .FromJust());
}

THREADED_TEST(CreationContext) {
  v8::Isolate* isolate = CcTest::isolate();
  HandleScope handle_scope(isolate);
  Local<Context> context1 = Context::New(isolate);
  InstallContextId(context1, 1);
  Local<Context> context2 = Context::New(isolate);
  InstallContextId(context2, 2);
  Local<Context> context3 = Context::New(isolate);
  InstallContextId(context3, 3);

  Local<v8::FunctionTemplate> tmpl = v8::FunctionTemplate::New(isolate);

  Local<Object> object1;
  Local<Function> func1;
  {
    Context::Scope scope(context1);
    object1 = Object::New(isolate);
    func1 = tmpl->GetFunction(context1).ToLocalChecked();
  }

  Local<Object> object2;
  Local<Function> func2;
  {
    Context::Scope scope(context2);
    object2 = Object::New(isolate);
    func2 = tmpl->GetFunction(context2).ToLocalChecked();
  }

  Local<Object> instance1;
  Local<Object> instance2;

  {
    Context::Scope scope(context3);
    instance1 = func1->NewInstance(context3).ToLocalChecked();
    instance2 = func2->NewInstance(context3).ToLocalChecked();
  }

  {
    Local<Context> other_context = Context::New(isolate);
    Context::Scope scope(other_context);
    START_ALLOW_USE_DEPRECATED();
    CHECK(object1->GetCreationContext().ToLocalChecked() == context1);
    CHECK(object1->GetCreationContextChecked() == context1);
    END_ALLOW_USE_DEPRECATED();
    CHECK(object1->GetCreationContext(isolate).ToLocalChecked() == context1);
    CHECK(object1->GetCreationContextChecked(isolate) == context1);
    CheckContextId(object1, 1);
    START_ALLOW_USE_DEPRECATED();
    CHECK(func1->GetCreationContext().ToLocalChecked() == context1);
    CHECK(func1->GetCreationContextChecked() == context1);
    END_ALLOW_USE_DEPRECATED();
    CHECK(func1->GetCreationContext(isolate).ToLocalChecked() == context1);
    CHECK(func1->GetCreationContextChecked(isolate) == context1);
    CheckContextId(func1, 1);
    START_ALLOW_USE_DEPRECATED();
    CHECK(instance1->GetCreationContext().ToLocalChecked() == context1);
    CHECK(instance1->GetCreationContextChecked() == context1);
    END_ALLOW_USE_DEPRECATED();
    CHECK(instance1->GetCreationContext(isolate).ToLocalChecked() == context1);
    CHECK(instance1->GetCreationContextChecked(isolate) == context1);
    CheckContextId(instance1, 1);
    START_ALLOW_USE_DEPRECATED();
    CHECK(object2->GetCreationContext().ToLocalChecked() == context2);
    CHECK(object2->GetCreationContextChecked() == context2);
    END_ALLOW_USE_DEPRECATED();
    CHECK(object2->GetCreationContext(isolate).ToLocalChecked() == context2);
    CHECK(object2->GetCreationContextChecked(isolate) == context2);
    CheckContextId(object2, 2);
    START_ALLOW_USE_DEPRECATED();
    CHECK(func2->GetCreationContext().ToLocalChecked() == context2);
    CHECK(func2->GetCreationContextChecked() == context2);
    END_ALLOW_USE_DEPRECATED();
    CHECK(func2->GetCreationContext(isolate).ToLocalChecked() == context2);
    CHECK(func2->GetCreationContextChecked(isolate) == context2);
    CheckContextId(func2, 2);
    START_ALLOW_USE_DEPRECATED();
    CHECK(instance2->GetCreationContext().ToLocalChecked() == context2);
    CHECK(instance2->GetCreationContextChecked() == context2);
    END_ALLOW_USE_DEPRECATED();
    CHECK(instance2->GetCreationContext(isolate).ToLocalChecked() == context2);
    CHECK(instance2->GetCreationContextChecked(isolate) == context2);
    CheckContextId(instance2, 2);
  }

  {
    Context::Scope scope(context1);
    START_ALLOW_USE_DEPRECATED();
    CHECK(object1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(object1, 1);
    CHECK(func1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(func1, 1);
    CHECK(instance1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(instance1, 1);
    CHECK(object2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(object2, 2);
    CHECK(func2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(func2, 2);
    CHECK(instance2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(instance2, 2);
    END_ALLOW_USE_DEPRECATED();
  }

  {
    Context::Scope scope(context2);
    START_ALLOW_USE_DEPRECATED();
    CHECK(object1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(object1, 1);
    CHECK(func1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(func1, 1);
    CHECK(instance1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(instance1, 1);
    CHECK(object2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(object2, 2);
    CHECK(func2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(func2, 2);
    CHECK(instance2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(instance2, 2);
    END_ALLOW_USE_DEPRECATED();
  }
}

THREADED_TEST(CreationContextOfJsFunction) {
  HandleScope handle_scope(CcTest::isolate());
  Local<Context> context = Context::New(CcTest::isolate());
  InstallContextId(context, 1);

  Local<Object> function;
  {
    Context::Scope scope(context);
    function = CompileRun("function foo() {}; foo").As<Object>();
  }

  Local<Context> other_context = Context::New(CcTest::isolate());
  Context::Scope scope(other_context);
  START_ALLOW_USE_DEPRECATED();
  CHECK(function->GetCreationContext().ToLocalChecked() == context);
  END_ALLOW_USE_DEPRECATED();
  CheckContextId(function, 1);
}

THREADED_TEST(CreationContextOfJsBoundFunction) {
  HandleScope handle_scope(CcTest::isolate());
  Local<Context> context1 = Context::New(CcTest::isolate());
  InstallContextId(context1, 1);
  Local<Context> context2 = Context::New(CcTest::isolate());
  InstallContextId(context2, 2);

  Local<Function> target_function;
  {
    Context::Scope scope(context1);
    target_function = CompileRun("function foo() {}; foo").As<Function>();
  }

  Local<Function> bound_function1, bound_function2;
  {
    Context::Scope scope(context2);
    CHECK(context2->Global()
              ->Set(context2, v8_str("foo"), target_function)
              .FromJust());
    bound_function1 = CompileRun("foo.bind(1)").As<Function>();
    bound_function2 =
        CompileRun("Function.prototype.bind.call(foo, 2)").As<Function>();
  }

  Local<Context> other_context = Context::New(CcTest::isolate());
  Context::Scope scope(other_context);
  START_ALLOW_USE_DEPRECATED();
  CHECK(bound_function1->GetCreationContext().ToLocalChecked() == context1);
  CheckContextId(bound_function1, 1);
  CHECK(bound_function2->GetCreationContext().ToLocalChecked() == context1);
  CheckContextId(bound_function2, 1);
  END_ALLOW_USE_DEPRECATED();
}

v8::Intercepted HasOwnPropertyIndexedPropertyGetter(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (index == 42) {
    info.GetReturnValue().Set(v8_str("yes"));
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted HasOwnPropertyNamedPropertyGetter(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (property->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("foo"))
          .FromJust()) {
    info.GetReturnValue().Set(v8_str("yes"));
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted HasOwnPropertyIndexedPropertyQuery(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (index == 42) {
    info.GetReturnValue().Set(v8::None);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted HasOwnPropertyNamedPropertyQuery(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (property->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("foo"))
          .FromJust()) {
    info.GetReturnValue().Set(v8::None);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted HasOwnPropertyNamedPropertyQuery2(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (property->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("bar"))
          .FromJust()) {
    info.GetReturnValue().Set(v8::None);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

void HasOwnPropertyAccessorGetter(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_str("yes"));
}

v8::Intercepted HasOwnPropertyAccessorNameGetter(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_str("yes"));
  return v8::Intercepted::kYes;
}

TEST(HasOwnProperty) {
  LocalContext env;
  v8::Isolate* isolate =
Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第22部分，共36部分，请归纳一下它的功能

"""
late::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);
    Local<Value> v = CompileRun("2");
    CHECK(v->IsNumber());
    CHECK_EQ(2, static_cast<int>(v->NumberValue(context).FromJust()));
  }
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);
    Local<Value> v = CompileRun("22");
    CHECK(v->IsNumber());
    CHECK_EQ(22, static_cast<int>(v->NumberValue(context).FromJust()));
  }
  isolate->Dispose();
}

class InitDefaultIsolateThread : public v8::base::Thread {
 public:
  enum TestCase {
    SetFatalHandler,
    SetCounterFunction,
    SetCreateHistogramFunction,
    SetAddHistogramSampleFunction
  };

  explicit InitDefaultIsolateThread(TestCase testCase)
      : Thread(Options("InitDefaultIsolateThread")),
        testCase_(testCase),
        result_(false) {}

  void Run() override {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    isolate->Enter();
    switch (testCase_) {
      case SetFatalHandler:
        isolate->SetFatalErrorHandler(nullptr);
        break;

      case SetCounterFunction:
        CcTest::isolate()->SetCounterFunction(nullptr);
        break;

      case SetCreateHistogramFunction:
        CcTest::isolate()->SetCreateHistogramFunction(nullptr);
        break;

      case SetAddHistogramSampleFunction:
        CcTest::isolate()->SetAddHistogramSampleFunction(nullptr);
        break;
    }
    isolate->Exit();
    isolate->Dispose();
    result_ = true;
  }

  bool result() { return result_; }

 private:
  TestCase testCase_;
  bool result_;
};


static void InitializeTestHelper(InitDefaultIsolateThread::TestCase testCase) {
  InitDefaultIsolateThread thread(testCase);
  CHECK(thread.Start());
  thread.Join();
  CHECK(thread.result());
}

TEST(InitializeDefaultIsolateOnSecondaryThread_FatalHandler) {
  InitializeTestHelper(InitDefaultIsolateThread::SetFatalHandler);
}

TEST(InitializeDefaultIsolateOnSecondaryThread_CounterFunction) {
  InitializeTestHelper(InitDefaultIsolateThread::SetCounterFunction);
}

TEST(InitializeDefaultIsolateOnSecondaryThread_CreateHistogramFunction) {
  InitializeTestHelper(InitDefaultIsolateThread::SetCreateHistogramFunction);
}

TEST(InitializeDefaultIsolateOnSecondaryThread_AddHistogramSampleFunction) {
  InitializeTestHelper(InitDefaultIsolateThread::SetAddHistogramSampleFunction);
}


TEST(StringCheckMultipleContexts) {
  const char* code =
      "(function() { return \"a\".charAt(0); })()";

  {
    // Run the code twice in the first context to initialize the call IC.
    LocalContext context1;
    v8::HandleScope scope(context1->GetIsolate());
    ExpectString(code, "a");
    ExpectString(code, "a");
  }

  {
    // Change the String.prototype in the second context and check
    // that the right function gets called.
    LocalContext context2;
    v8::HandleScope scope(context2->GetIsolate());
    CompileRun("String.prototype.charAt = function() { return \"not a\"; }");
    ExpectString(code, "not a");
  }
}


TEST(NumberCheckMultipleContexts) {
  const char* code =
      "(function() { return (42).toString(); })()";

  {
    // Run the code twice in the first context to initialize the call IC.
    LocalContext context1;
    v8::HandleScope scope(context1->GetIsolate());
    ExpectString(code, "42");
    ExpectString(code, "42");
  }

  {
    // Change the Number.prototype in the second context and check
    // that the right function gets called.
    LocalContext context2;
    v8::HandleScope scope(context2->GetIsolate());
    CompileRun("Number.prototype.toString = function() { return \"not 42\"; }");
    ExpectString(code, "not 42");
  }
}


TEST(BooleanCheckMultipleContexts) {
  const char* code =
      "(function() { return true.toString(); })()";

  {
    // Run the code twice in the first context to initialize the call IC.
    LocalContext context1;
    v8::HandleScope scope(context1->GetIsolate());
    ExpectString(code, "true");
    ExpectString(code, "true");
  }

  {
    // Change the Boolean.prototype in the second context and check
    // that the right function gets called.
    LocalContext context2;
    v8::HandleScope scope(context2->GetIsolate());
    CompileRun("Boolean.prototype.toString = function() { return \"\"; }");
    ExpectString(code, "");
  }
}


TEST(DontDeleteCellLoadIC) {
  const char* function_code =
      "function readCell() { while (true) { return cell; } }";

  {
    // Run the code twice in the first context to initialize the load
    // IC for a don't delete cell.
    LocalContext context1;
    v8::HandleScope scope(context1->GetIsolate());
    CompileRun("var cell = \"first\";");
    ExpectBoolean("delete cell", false);
    CompileRun(function_code);
    ExpectString("readCell()", "first");
    ExpectString("readCell()", "first");
  }

  {
    // Use a deletable cell in the second context.
    LocalContext context2;
    v8::HandleScope scope(context2->GetIsolate());
    CompileRun("cell = \"second\";");
    CompileRun(function_code);
    ExpectString("readCell()", "second");
    ExpectBoolean("delete cell", true);
    ExpectString("(function() {"
                 "  try {"
                 "    return readCell();"
                 "  } catch(e) {"
                 "    return e.toString();"
                 "  }"
                 "})()",
                 "ReferenceError: cell is not defined");
    CompileRun("cell = \"new_second\";");
    i::heap::InvokeMajorGC(CcTest::heap());
    ExpectString("readCell()", "new_second");
    ExpectString("readCell()", "new_second");
  }
}

TEST(WrapperClassId) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Persistent<v8::Object> object(isolate, v8::Object::New(isolate));
  CHECK_EQ(0, object.WrapperClassId());
  object.SetWrapperClassId(65535);
  CHECK_EQ(65535, object.WrapperClassId());
  object.Reset();
}

TEST(RegExp) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  v8::Local<v8::RegExp> re =
      v8::RegExp::New(context.local(), v8_str("foo"), v8::RegExp::kNone)
          .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("foo")).FromJust());
  CHECK_EQ(v8::RegExp::kNone, re->GetFlags());

  re = v8::RegExp::New(context.local(), v8_str("foo/bar"), v8::RegExp::kNone)
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(
      re->GetSource()->Equals(context.local(), v8_str("foo\\/bar")).FromJust());
  CHECK_EQ(v8::RegExp::kNone, re->GetFlags());

  re = v8::RegExp::New(context.local(), v8_str("bar"),
                       static_cast<v8::RegExp::Flags>(v8::RegExp::kIgnoreCase |
                                                      v8::RegExp::kGlobal))
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("bar")).FromJust());
  CHECK_EQ(v8::RegExp::kIgnoreCase | v8::RegExp::kGlobal,
           static_cast<int>(re->GetFlags()));

  re = v8::RegExp::New(context.local(), v8_str("baz"),
                       static_cast<v8::RegExp::Flags>(v8::RegExp::kIgnoreCase |
                                                      v8::RegExp::kMultiline))
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("baz")).FromJust());
  CHECK_EQ(v8::RegExp::kIgnoreCase | v8::RegExp::kMultiline,
           static_cast<int>(re->GetFlags()));

  re = v8::RegExp::New(context.local(), v8_str("baz"),
                       static_cast<v8::RegExp::Flags>(v8::RegExp::kUnicode |
                                                      v8::RegExp::kSticky))
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("baz")).FromJust());
  CHECK_EQ(v8::RegExp::kUnicode | v8::RegExp::kSticky,
           static_cast<int>(re->GetFlags()));

  re = CompileRun("/quux/").As<v8::RegExp>();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("quux")).FromJust());
  CHECK_EQ(v8::RegExp::kNone, re->GetFlags());

  re = CompileRun("RegExp('qu/ux')").As<v8::RegExp>();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("qu\\/ux")).FromJust());
  CHECK_EQ(v8::RegExp::kNone, re->GetFlags());

  re = CompileRun("/quux/gm").As<v8::RegExp>();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("quux")).FromJust());
  CHECK_EQ(v8::RegExp::kGlobal | v8::RegExp::kMultiline,
           static_cast<int>(re->GetFlags()));

  // Override the RegExp constructor and check the API constructor
  // still works.
  CompileRun("RegExp = function() {}");

  re = v8::RegExp::New(context.local(), v8_str("foobar"), v8::RegExp::kNone)
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("foobar")).FromJust());
  CHECK_EQ(v8::RegExp::kNone, re->GetFlags());

  re = v8::RegExp::New(context.local(), v8_str("foobarbaz"),
                       static_cast<v8::RegExp::Flags>(v8::RegExp::kIgnoreCase |
                                                      v8::RegExp::kMultiline))
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(
      re->GetSource()->Equals(context.local(), v8_str("foobarbaz")).FromJust());
  CHECK_EQ(v8::RegExp::kIgnoreCase | v8::RegExp::kMultiline,
           static_cast<int>(re->GetFlags()));

  CHECK(context->Global()->Set(context.local(), v8_str("re"), re).FromJust());
  ExpectTrue("re.test('FoobarbaZ')");

  // RegExps are objects on which you can set properties.
  re->Set(context.local(), v8_str("property"),
          v8::Integer::New(context->GetIsolate(), 32))
      .FromJust();
  v8::Local<v8::Value> value(CompileRun("re.property"));
  CHECK_EQ(32, value->Int32Value(context.local()).FromJust());

  {
    v8::TryCatch try_catch(context->GetIsolate());
    CHECK(v8::RegExp::New(context.local(), v8_str("foo["), v8::RegExp::kNone)
              .IsEmpty());
    CHECK(try_catch.HasCaught());
    CHECK(context->Global()
              ->Set(context.local(), v8_str("ex"), try_catch.Exception())
              .FromJust());
    ExpectTrue("ex instanceof SyntaxError");
  }

  // RegExp::Exec.
  {
    v8::Local<v8::RegExp> regexp =
        v8::RegExp::New(context.local(), v8_str("a.c"), {}).ToLocalChecked();
    v8::Local<v8::Object> result0 =
        regexp->Exec(context.local(), v8_str("abc")).ToLocalChecked();
    CHECK(result0->IsArray());
    v8::Local<v8::Object> result1 =
        regexp->Exec(context.local(), v8_str("abd")).ToLocalChecked();
    CHECK(result1->IsNull());
  }
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
START_ALLOW_USE_DEPRECATED()

THREADED_TEST(Equals) {
  LocalContext localContext;
  v8::HandleScope handleScope(localContext->GetIsolate());

  v8::Local<v8::Object> globalProxy = localContext->Global();
  v8::Local<Value> global = globalProxy->GetPrototype();

  CHECK(global->StrictEquals(global));
  CHECK(!global->StrictEquals(globalProxy));
  CHECK(!globalProxy->StrictEquals(global));
  CHECK(globalProxy->StrictEquals(globalProxy));

  CHECK(global->Equals(localContext.local(), global).FromJust());
  CHECK(!global->Equals(localContext.local(), globalProxy).FromJust());
  CHECK(!globalProxy->Equals(localContext.local(), global).FromJust());
  CHECK(globalProxy->Equals(localContext.local(), globalProxy).FromJust());
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
END_ALLOW_USE_DEPRECATED()

namespace {
v8::Intercepted Getter(v8::Local<v8::Name> property,
                       const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_str("42!"));
  return v8::Intercepted::kYes;
}

void Enumerator(const v8::PropertyCallbackInfo<v8::Array>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::Local<v8::Array> result = v8::Array::New(info.GetIsolate());
  result->Set(info.GetIsolate()->GetCurrentContext(), 0,
              v8_str("universalAnswer"))
      .FromJust();
  info.GetReturnValue().Set(result);
}
}  // namespace

TEST(NamedEnumeratorAndForIn) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  v8::Context::Scope context_scope(context.local());

  v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);
  tmpl->SetHandler(v8::NamedPropertyHandlerConfiguration(
      Getter, nullptr, nullptr, nullptr, Enumerator));
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o"),
                  tmpl->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  v8::Local<v8::Array> result = v8::Local<v8::Array>::Cast(
      CompileRun("var result = []; for (var k in o) result.push(k); result"));
  CHECK_EQ(1u, result->Length());
  CHECK(v8_str("universalAnswer")
            ->Equals(context.local(),
                     result->Get(context.local(), 0).ToLocalChecked())
            .FromJust());
}


TEST(DefinePropertyPostDetach) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::Local<v8::Object> proxy = context->Global();
  v8::Local<v8::Function> define_property =
      CompileRun(
          "(function() {"
          "  Object.defineProperty("
          "    this,"
          "    1,"
          "    { configurable: true, enumerable: true, value: 3 });"
          "})")
          .As<Function>();
  context->DetachGlobal();
  CHECK(define_property->Call(context.local(), proxy, 0, nullptr).IsEmpty());
}


static void InstallContextId(v8::Local<Context> context, int id) {
  Context::Scope scope(context);
  CHECK(CompileRun("Object.prototype")
            .As<Object>()
            ->Set(context, v8_str("context_id"),
                  v8::Integer::New(context->GetIsolate(), id))
            .FromJust());
}


static void CheckContextId(v8::Local<Object> object, int expected) {
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  CHECK_EQ(expected, object->Get(context, v8_str("context_id"))
                         .ToLocalChecked()
                         ->Int32Value(context)
                         .FromJust());
}


THREADED_TEST(CreationContext) {
  v8::Isolate* isolate = CcTest::isolate();
  HandleScope handle_scope(isolate);
  Local<Context> context1 = Context::New(isolate);
  InstallContextId(context1, 1);
  Local<Context> context2 = Context::New(isolate);
  InstallContextId(context2, 2);
  Local<Context> context3 = Context::New(isolate);
  InstallContextId(context3, 3);

  Local<v8::FunctionTemplate> tmpl = v8::FunctionTemplate::New(isolate);

  Local<Object> object1;
  Local<Function> func1;
  {
    Context::Scope scope(context1);
    object1 = Object::New(isolate);
    func1 = tmpl->GetFunction(context1).ToLocalChecked();
  }

  Local<Object> object2;
  Local<Function> func2;
  {
    Context::Scope scope(context2);
    object2 = Object::New(isolate);
    func2 = tmpl->GetFunction(context2).ToLocalChecked();
  }

  Local<Object> instance1;
  Local<Object> instance2;

  {
    Context::Scope scope(context3);
    instance1 = func1->NewInstance(context3).ToLocalChecked();
    instance2 = func2->NewInstance(context3).ToLocalChecked();
  }

  {
    Local<Context> other_context = Context::New(isolate);
    Context::Scope scope(other_context);
    START_ALLOW_USE_DEPRECATED();
    CHECK(object1->GetCreationContext().ToLocalChecked() == context1);
    CHECK(object1->GetCreationContextChecked() == context1);
    END_ALLOW_USE_DEPRECATED();
    CHECK(object1->GetCreationContext(isolate).ToLocalChecked() == context1);
    CHECK(object1->GetCreationContextChecked(isolate) == context1);
    CheckContextId(object1, 1);
    START_ALLOW_USE_DEPRECATED();
    CHECK(func1->GetCreationContext().ToLocalChecked() == context1);
    CHECK(func1->GetCreationContextChecked() == context1);
    END_ALLOW_USE_DEPRECATED();
    CHECK(func1->GetCreationContext(isolate).ToLocalChecked() == context1);
    CHECK(func1->GetCreationContextChecked(isolate) == context1);
    CheckContextId(func1, 1);
    START_ALLOW_USE_DEPRECATED();
    CHECK(instance1->GetCreationContext().ToLocalChecked() == context1);
    CHECK(instance1->GetCreationContextChecked() == context1);
    END_ALLOW_USE_DEPRECATED();
    CHECK(instance1->GetCreationContext(isolate).ToLocalChecked() == context1);
    CHECK(instance1->GetCreationContextChecked(isolate) == context1);
    CheckContextId(instance1, 1);
    START_ALLOW_USE_DEPRECATED();
    CHECK(object2->GetCreationContext().ToLocalChecked() == context2);
    CHECK(object2->GetCreationContextChecked() == context2);
    END_ALLOW_USE_DEPRECATED();
    CHECK(object2->GetCreationContext(isolate).ToLocalChecked() == context2);
    CHECK(object2->GetCreationContextChecked(isolate) == context2);
    CheckContextId(object2, 2);
    START_ALLOW_USE_DEPRECATED();
    CHECK(func2->GetCreationContext().ToLocalChecked() == context2);
    CHECK(func2->GetCreationContextChecked() == context2);
    END_ALLOW_USE_DEPRECATED();
    CHECK(func2->GetCreationContext(isolate).ToLocalChecked() == context2);
    CHECK(func2->GetCreationContextChecked(isolate) == context2);
    CheckContextId(func2, 2);
    START_ALLOW_USE_DEPRECATED();
    CHECK(instance2->GetCreationContext().ToLocalChecked() == context2);
    CHECK(instance2->GetCreationContextChecked() == context2);
    END_ALLOW_USE_DEPRECATED();
    CHECK(instance2->GetCreationContext(isolate).ToLocalChecked() == context2);
    CHECK(instance2->GetCreationContextChecked(isolate) == context2);
    CheckContextId(instance2, 2);
  }

  {
    Context::Scope scope(context1);
    START_ALLOW_USE_DEPRECATED();
    CHECK(object1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(object1, 1);
    CHECK(func1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(func1, 1);
    CHECK(instance1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(instance1, 1);
    CHECK(object2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(object2, 2);
    CHECK(func2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(func2, 2);
    CHECK(instance2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(instance2, 2);
    END_ALLOW_USE_DEPRECATED();
  }

  {
    Context::Scope scope(context2);
    START_ALLOW_USE_DEPRECATED();
    CHECK(object1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(object1, 1);
    CHECK(func1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(func1, 1);
    CHECK(instance1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(instance1, 1);
    CHECK(object2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(object2, 2);
    CHECK(func2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(func2, 2);
    CHECK(instance2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(instance2, 2);
    END_ALLOW_USE_DEPRECATED();
  }
}


THREADED_TEST(CreationContextOfJsFunction) {
  HandleScope handle_scope(CcTest::isolate());
  Local<Context> context = Context::New(CcTest::isolate());
  InstallContextId(context, 1);

  Local<Object> function;
  {
    Context::Scope scope(context);
    function = CompileRun("function foo() {}; foo").As<Object>();
  }

  Local<Context> other_context = Context::New(CcTest::isolate());
  Context::Scope scope(other_context);
  START_ALLOW_USE_DEPRECATED();
  CHECK(function->GetCreationContext().ToLocalChecked() == context);
  END_ALLOW_USE_DEPRECATED();
  CheckContextId(function, 1);
}


THREADED_TEST(CreationContextOfJsBoundFunction) {
  HandleScope handle_scope(CcTest::isolate());
  Local<Context> context1 = Context::New(CcTest::isolate());
  InstallContextId(context1, 1);
  Local<Context> context2 = Context::New(CcTest::isolate());
  InstallContextId(context2, 2);

  Local<Function> target_function;
  {
    Context::Scope scope(context1);
    target_function = CompileRun("function foo() {}; foo").As<Function>();
  }

  Local<Function> bound_function1, bound_function2;
  {
    Context::Scope scope(context2);
    CHECK(context2->Global()
              ->Set(context2, v8_str("foo"), target_function)
              .FromJust());
    bound_function1 = CompileRun("foo.bind(1)").As<Function>();
    bound_function2 =
        CompileRun("Function.prototype.bind.call(foo, 2)").As<Function>();
  }

  Local<Context> other_context = Context::New(CcTest::isolate());
  Context::Scope scope(other_context);
  START_ALLOW_USE_DEPRECATED();
  CHECK(bound_function1->GetCreationContext().ToLocalChecked() == context1);
  CheckContextId(bound_function1, 1);
  CHECK(bound_function2->GetCreationContext().ToLocalChecked() == context1);
  CheckContextId(bound_function2, 1);
  END_ALLOW_USE_DEPRECATED();
}

v8::Intercepted HasOwnPropertyIndexedPropertyGetter(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (index == 42) {
    info.GetReturnValue().Set(v8_str("yes"));
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted HasOwnPropertyNamedPropertyGetter(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (property->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("foo"))
          .FromJust()) {
    info.GetReturnValue().Set(v8_str("yes"));
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted HasOwnPropertyIndexedPropertyQuery(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (index == 42) {
    info.GetReturnValue().Set(v8::None);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted HasOwnPropertyNamedPropertyQuery(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (property->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("foo"))
          .FromJust()) {
    info.GetReturnValue().Set(v8::None);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted HasOwnPropertyNamedPropertyQuery2(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (property->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("bar"))
          .FromJust()) {
    info.GetReturnValue().Set(v8::None);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

void HasOwnPropertyAccessorGetter(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_str("yes"));
}

v8::Intercepted HasOwnPropertyAccessorNameGetter(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_str("yes"));
  return v8::Intercepted::kYes;
}

TEST(HasOwnProperty) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  { // Check normal properties and defined getters.
    Local<Value> value = CompileRun(
        "function Foo() {"
        "    this.foo = 11;"
        "    this.__defineGetter__('baz', function() { return 1; });"
        "};"
        "function Bar() { "
        "    this.bar = 13;"
        "    this.__defineGetter__('bla', function() { return 2; });"
        "};"
        "Bar.prototype = new Foo();"
        "new Bar();");
    CHECK(value->IsObject());
    Local<Object> object = value->ToObject(env.local()).ToLocalChecked();
    CHECK(object->Has(env.local(), v8_str("foo")).FromJust());
    CHECK(!object->HasOwnProperty(env.local(), v8_str("foo")).FromJust());
    CHECK(object->HasOwnProperty(env.local(), v8_str("bar")).FromJust());
    CHECK(object->Has(env.local(), v8_str("baz")).FromJust());
    CHECK(!object->HasOwnProperty(env.local(), v8_str("baz")).FromJust());
    CHECK(object->HasOwnProperty(env.local(), v8_str("bla")).FromJust());
  }
  { // Check named getter interceptors.
    Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
    templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
        HasOwnPropertyNamedPropertyGetter));
    Local<Object> instance = templ->NewInstance(env.local()).ToLocalChecked();
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("42")).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), 42).FromJust());
    CHECK(instance->HasOwnProperty(env.local(), v8_str("foo")).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("bar")).FromJust());
  }
  { // Check indexed getter interceptors.
    Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
    templ->SetHandler(v8::IndexedPropertyHandlerConfiguration(
        HasOwnPropertyIndexedPropertyGetter));
    Local<Object> instance = templ->NewInstance(env.local()).ToLocalChecked();
    CHECK(instance->HasOwnProperty(env.local(), v8_str("42")).FromJust());
    CHECK(instance->HasOwnProperty(env.local(), 42).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("43")).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), 43).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("foo")).FromJust());
  }
  { // Check named query interceptors.
    Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
    templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
        nullptr, nullptr, HasOwnPropertyNamedPropertyQuery));
    Local<Object> instance = templ->NewInstance(env.local()).ToLocalChecked();
    CHECK(instance->HasOwnProperty(env.local(), v8_str("foo")).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("bar")).FromJust());
  }
  { // Check indexed query interceptors.
    Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
    templ->SetHandler(v8::IndexedPropertyHandlerConfiguration(
        nullptr, nullptr, HasOwnPropertyIndexedPropertyQuery));
    Local<Object> instance = templ->NewInstance(env.local()).ToLocalChecked();
    CHECK(instance->HasOwnProperty(env.local(), v8_str("42")).FromJust());
    CHECK(instance->HasOwnProperty(env.local(), 42).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("41")).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), 41).FromJust());
  }
  { // Check callbacks.
    Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
    templ->SetNativeDataProperty(v8_str("foo"), HasOwnPropertyAccessorGetter);
    Local<Object> instance = templ->NewInstance(env.local()).ToLocalChecked();
    CHECK(instance->HasOwnProperty(env.local(), v8_str("foo")).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("bar")).FromJust());
  }
  { // Check that query wins on disagreement.
    Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
    templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
        HasOwnPropertyNamedPropertyGetter, nullptr,
        HasOwnPropertyNamedPropertyQuery2));
    Local<Object> instance = templ->NewInstance(env.local()).ToLocalChecked();
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("foo")).FromJust());
    CHECK(instance->HasOwnProperty(env.local(), v8_str("bar")).FromJust());
  }
  {  // Check that non-internalized keys are handled correctly.
    Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
    templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
        HasOwnPropertyAccessorNameGetter));
    Local<Object> instance = templ->NewInstance(env.local()).ToLocalChecked();
    env->Global()->Set(env.local(), v8_str("obj"), instance).FromJust();
    const char* src =
        "var dyn_string = 'this string ';"
        "dyn_string += 'does not exist elsewhere';"
        "({}).hasOwnProperty.call(obj, dyn_string)";
    CHECK(CompileRun(src)->BooleanValue(isolate));
  }
}


TEST(IndexedInterceptorWithStringProto) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      nullptr, nullptr, HasOwnPropertyIndexedPropertyQuery));
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  CompileRun("var s = new String('foobar'); obj.__proto__ = s;");
  // These should be intercepted.
  CHECK(CompileRun("42 in obj")->BooleanValue(isolate));
  CHECK(CompileRun("'42' in obj")->BooleanValue(isolate));
  // These should fall through to the String prototype.
  CHECK(CompileRun("0 in obj")->BooleanValue(isolate));
  CHECK(CompileRun("'0' in obj")->BooleanValue(isolate));
  // And these should both fail.
  CHECK(!CompileRun("32 in obj")->BooleanValue(isolate));
  CHECK(!CompileRun("'32' in obj")->BooleanValue(isolate));
}


void CheckCodeGenerationAllowed() {
  Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  Local<Value> result = CompileRun("eval('42')");
  CHECK_EQ(42, result->Int32Value(context).FromJust());
  result = CompileRun("(function(e) { return e('42'); })(eval)");
  CHECK_EQ(42, result->Int32Value(context).FromJust());
  result = CompileRun("var f = new Function('return 42'); f()");
  CHECK_EQ(42, result->Int32Value(context).FromJust());
}


void CheckCodeGenerationDisallowed() {
  TryCatch try_catch(CcTest::isolate());

  Local<Value> result = CompileRun("eval('42')");
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  result = CompileRun("(function(e) { return e('42'); })(eval)");
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  result = CompileRun("var f = new Function('return 42'); f()");
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
}

char first_fourty_bytes[41];

v8::ModifyCodeGenerationFromStringsResult CodeGenerationAllowed(
    Local<Context> context, Local<Value> source, bool is_code_like) {
  String::Utf8Value str(CcTest::isolate(), source);
  size_t len = std::min(sizeof(first_fourty_bytes) - 1,
                        static_cast<size_t>(str.length()));
  strncpy(first_fourty_bytes, *str, len);
  first_fourty_bytes[len] = 0;
  ApiTestFuzzer::Fuzz();
  return {true, {}};
}

v8::ModifyCodeGenerationFromStringsResult CodeGenerationDisallowed(
    Local<Context> context, Local<Value> source, bool is_code_like) {
  ApiTestFuzzer::Fuzz();
  return {false, {}};
}

v8::ModifyCodeGenerationFromStringsResult ModifyCodeGeneration(
    Local<Context> context, Local<Value> source, bool is_code_like) {
  // Allow (passthrough, unmodified) all objects that are not strings.
  if (!source->IsString()) {
    return {/* codegen_allowed= */ true, v8::MaybeLocal<String>()};
  }

  String::Utf8Value utf8(context->GetIsolate(), source);
  DCHECK_GT(utf8.length(), 0);

  // Allow (unmodified) all strings that contain "44".
  if (strstr(*utf8, "44") != nullptr) {
    return {/* codegen_allowed= */ true, v8::MaybeLocal<String>()};
  }

  // Deny all odd-length strings.
  if (utf8.length() == 0 || utf8.length() % 2 != 0) {
    return {/* codegen_allowed= */ false, v8::MaybeLocal<String>()};
  }

  // Allow even-length strings and modify them by replacing all '2' with '3'.
  for (char* i = *utf8; *i != '\0'; i++) {
    if (*i == '2') *i = '3';
  }
  return {/* codegen_allowed= */ true,
          String::NewFromUtf8(context->GetIsolate(), *utf8).ToLocalChecked()};
}

THREADED_TEST(AllowCodeGenFromStrings) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  // eval and the Function constructor allowed by default.
  CHECK(context->IsCodeGenerationFromStringsAllowed());
  CheckCodeGenerationAllowed();

  // Disallow eval and the Function constructor.
  context->AllowCodeGenerationFromStrings(false);
  CHECK(!context->IsCodeGenerationFromStringsAllowed());
  CheckCodeGenerationDisallowed();

  // Allow again.
  context->AllowCodeGenerationFromStrings(true);
  CheckCodeGenerationAllowed();

  // Disallow but setting a global callback that will allow the calls.
  context->AllowCodeGenerationFromStrings(false);
  context->GetIsolate()->SetModifyCodeGenerationFromStringsCallback(
      &CodeGenerationAllo
"""


```