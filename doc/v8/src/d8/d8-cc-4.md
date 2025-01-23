Response:
Let's break down the thought process for analyzing this code snippet and fulfilling the prompt's requirements.

**1. Understanding the Goal:**

The primary goal is to analyze a specific code snippet from `v8/src/d8/d8.cc` and describe its functionality, relating it to JavaScript where possible, illustrating with examples, and summarizing its purpose within the larger file.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code, looking for familiar keywords and patterns. This helps in forming initial hypotheses about the code's purpose. Some immediately noticeable elements are:

* **`Shell::ReportException`**:  This clearly deals with error reporting and exception handling.
* **`Counter`, `CounterCollection`**: These likely handle performance counters or some kind of statistics tracking.
* **`Shell::MapCounters`**: Suggests mapping counters to a file, possibly for persistence or external monitoring.
* **`Shell::GetCounter`**:  Indicates retrieval of counter objects.
* **`Shell::LookupCounter`, `Shell::CreateHistogram`, `Shell::AddHistogramSample`**: These are functions likely exposed to V8's internals for recording performance data.
* **`Shell::Stringify`**: A function to convert V8 values to strings, useful for debugging or output.
* **`Shell::NodeTypeCallback`**: A callback function, likely used for implementing some native API functionality.
* **`NewDOMFunctionTemplate`**:  Hints at the creation of templates for DOM-related JavaScript objects.
* **`Shell::CreateEventTargetTemplate`, `Shell::CreateNodeTemplates`**: Further reinforces the DOM object creation theme.
* **`Shell::CreateGlobalTemplate`**:  This is a crucial part, dealing with setting up the global object in the JavaScript environment. The various `global_template->Set` calls are key to understanding the available global functions and objects.
* **Functions like `Print`, `WriteStdout`, `ReadFile`, `load`, `setTimeout`, `quit`**: These are standard shell-like functionalities.
* **Objects like `testRunner`, `Realm`, `performance`, `Worker`, `os`, `d8`**: These suggest extensions or built-in modules provided by the d8 shell.
* **`Shell::CreateOSTemplate`, `Shell::CreateWorkerTemplate`, `Shell::CreateAsyncHookTemplate`, etc.**:  Functions dedicated to creating specific object templates, revealing the structure and capabilities of d8.
* **`Shell::CreateD8Template`**:  A template for a `d8` global object, which contains further sub-objects and functions. This is a major organizational element.
* **`PrintMessageCallback`**: Another callback, this time for handling V8 messages (errors, warnings, etc.).
* **`Shell::PromiseRejectCallback`**:  Handles unhandled promise rejections.
* **`Shell::Initialize`**:  A setup function for the shell environment.
* **`Shell::CreateEvaluationContext`**: Creates the initial JavaScript execution context.
* **`Shell::WriteIgnitionDispatchCountersFile`, `Shell::WriteLcovData`**: Functions for writing out performance or coverage data.
* **`Shell::OnExit`**: Cleanup and shutdown procedures.

**3. Grouping Functionality:**

Based on the keywords and patterns, the code can be grouped into logical units:

* **Exception Handling:**  `ReportException`
* **Performance Counters:** `Counter`, `CounterCollection`, `MapCounters`, `GetCounter`, `LookupCounter`, `CreateHistogram`, `AddHistogramSample`
* **String Conversion:** `Stringify`
* **DOM Support:** `NodeTypeCallback`, `NewDOMFunctionTemplate`, `CreateEventTargetTemplate`, `CreateNodeTemplates`
* **Global Object Setup:** `CreateGlobalTemplate` and the various `Create...Template` functions it calls (e.g., `CreateOSTemplate`, `CreateWorkerTemplate`, `CreateD8Template`). This is a large and important group.
* **Message Handling:** `PrintMessageCallback`
* **Promise Rejection Handling:** `PromiseRejectCallback`
* **Initialization and Context Creation:** `Initialize`, `CreateEvaluationContext`
* **Data Output:** `WriteIgnitionDispatchCountersFile`, `WriteLcovData`
* **Shutdown:** `OnExit`

**4. Analyzing Each Group and Generating Explanations:**

Now, go through each group and elaborate on its purpose, connecting it to JavaScript concepts where applicable.

* **Exception Handling:** Explain how it catches and reports errors, including stack traces. Provide a simple JavaScript `try...catch` example.
* **Performance Counters:** Explain the concept of counters and histograms for tracking performance metrics.
* **String Conversion:** Show how it relates to JavaScript's string conversion when logging or debugging.
* **DOM Support:** Explain that this section enables d8 to simulate a basic DOM environment, allowing testing of DOM-related JavaScript code. Provide a simple example of creating and accessing a DOM element.
* **Global Object Setup:**  This is the core of d8's environment. List the important global functions and objects and explain their purpose (e.g., `print`, `load`, `quit`, the `d8` object).
* **Message Handling:**  Explain how d8 handles and displays messages from the V8 engine.
* **Promise Rejection Handling:** Explain how unhandled promise rejections are caught and reported.
* **Initialization and Context Creation:** Describe the setup process for the V8 isolate and the creation of the global execution context.
* **Data Output:** Explain how d8 can output performance counter data and code coverage information.
* **Shutdown:** Describe the cleanup procedures when d8 exits.

**5. Addressing Specific Prompt Requirements:**

* **`.tq` extension:** Explain that if the file ended in `.tq`, it would be a Torque file.
* **JavaScript examples:** Provide concise JavaScript examples to illustrate the functionality where relevant.
* **Code logic inference:**  For counters, give examples of how the count and total might change with different inputs.
* **Common programming errors:** Relate the exception handling to common JavaScript `try...catch` usage and potential errors.
* **Part 5 of 8:** Summarize the overall functionality of this part of the `d8.cc` file. It's focused on setting up the execution environment, providing core functionalities (like printing, file I/O), and offering tools for debugging and performance analysis.

**6. Structuring the Output:**

Organize the analysis logically, starting with a general overview, then detailing each functional group, providing examples and addressing the prompt's specific points, and finally concluding with a summary. Use headings and bullet points for clarity.

**7. Review and Refinement:**

Read through the entire analysis to ensure accuracy, clarity, and completeness. Check that all aspects of the prompt have been addressed. Ensure the JavaScript examples are correct and relevant.

**Self-Correction/Refinement Example During the Process:**

Initially, I might focus too much on the individual functions. During the review, I'd realize the importance of grouping the functions by their purpose. For instance, all the `Create...Template` functions work together to define the global environment, so they should be discussed as a unit within that context. Similarly, the counter-related functions form a clear block of functionality. This shift from individual function analysis to functional group analysis leads to a more coherent and insightful explanation. Also, making sure the JavaScript examples directly illustrate the C++ code's actions is crucial. For example, when talking about `Shell::CreateGlobalTemplate` and `global_template->Set(isolate, "print", ...)`, showing a simple `print("hello")` in JavaScript clarifies the connection.
Based on the provided code snippet from `v8/src/d8/d8.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This section of `d8.cc` primarily focuses on:

1. **Exception Reporting:**  It provides mechanisms to catch and report exceptions that occur during JavaScript execution within the d8 shell. This includes printing the error message and the stack trace.

2. **Performance Counter Management:** It implements a system for tracking and reporting performance counters. This involves:
   - Defining `Counter` objects to store counts and totals.
   - A `CounterCollection` to manage a group of counters.
   - Functions to bind names to counters (`Bind`), add samples (`AddSample`), and map counters to a file (`MapCounters`).
   - Functions (`LookupCounter`, `CreateHistogram`, `AddHistogramSample`) that are likely called by V8's internal mechanisms to record performance data.

3. **String Conversion:** The `Stringify` function converts V8 values into human-readable strings. This is useful for displaying results and debugging.

4. **Simulating a Basic DOM Environment:** It starts to lay the groundwork for a minimal DOM (Document Object Model) environment within d8. This includes creating function templates for `EventTarget`, `Node`, `Element`, and specific HTML elements like `HTMLDivElement`. This allows d8 to potentially run some JavaScript code that interacts with basic DOM concepts.

5. **Setting up the Global Object:** The `CreateGlobalTemplate` function is crucial. It defines the global object that will be available in the d8 JavaScript environment. This includes:
   - Standard global functions like `print`, `printErr`, `write`, `read`, `load`, `setTimeout`, `quit`.
   - Objects like `testRunner`, `Realm`, `performance`, `Worker`, `os`, and `d8` itself, which provide additional functionalities and testing capabilities.

6. **Creating Sub-Object Templates:**  Several functions like `CreateOSTemplate`, `CreateWorkerTemplate`, `CreateAsyncHookTemplate`, `CreateTestRunnerTemplate`, `CreatePerformanceTemplate`, `CreateRealmTemplate`, and `CreateD8Template` are responsible for defining the structure and methods of the global objects mentioned above. This modular approach organizes the functionalities provided by d8.

7. **Handling V8 Messages and Promise Rejections:**  The `PrintMessageCallback` handles messages generated by the V8 engine (errors, warnings, etc.), and `PromiseRejectCallback` deals with unhandled promise rejections.

8. **Initialization:** The `Initialize` function sets up the V8 isolate for d8, including setting the promise rejection callback, and potentially mapping counters.

9. **Creating the Evaluation Context:** `CreateEvaluationContext` creates the initial JavaScript execution context, setting up the global object and potentially injecting command-line arguments into the environment.

10. **Writing Performance and Coverage Data:** Functions like `WriteIgnitionDispatchCountersFile` and `WriteLcovData` allow d8 to output performance-related data and code coverage information.

11. **Shutdown Procedures:** The `OnExit` function handles cleanup tasks when d8 terminates, including notifying the platform of the shutdown, potentially disposing of the isolate, and dumping performance counters.

**Is `v8/src/d8/d8.cc` a Torque source?**

No, based on the filename ending (`.cc`), `v8/src/d8/d8.cc` is a **C++ source file**, not a Torque source file. Torque source files typically end with `.tq`.

**Relationship to JavaScript with Examples:**

Many parts of this code directly relate to the JavaScript environment d8 provides:

* **`print` Function:**
   ```javascript
   // In d8:
   print("Hello, world!"); // This would call the Print function in d8.cc
   ```
* **Exception Handling:**
   ```javascript
   // In d8:
   try {
     throw new Error("Something went wrong");
   } catch (e) {
     // The ReportException function in d8.cc would be involved in displaying this error.
     printErr(e.stack);
   }
   ```
* **`setTimeout`:**
   ```javascript
   // In d8:
   setTimeout(() => {
     print("Delayed message");
   }, 1000); // The SetTimeout function in d8.cc handles this.
   ```
* **DOM Simulation:**
   ```javascript
   // In d8 (with DOM enabled/simulated):
   let div = document.createElement('div'); // This relates to the DOM creation functions.
   div.textContent = "Hello from DOM!";
   print(div.textContent);
   ```
* **`d8` Global Object:**
   ```javascript
   // In d8:
   d8.file.read("my_script.js"); // Calls the ReadFile function associated with the 'd8.file' object.
   ```
* **Performance Counters (Conceptual - direct access in JS might be limited):** While you might not directly access the counters from JavaScript in d8 as easily, V8 internally uses mechanisms linked to these C++ counters to track performance. You might indirectly see the effects through profiling tools or flags.

**Code Logic Inference (Example: Counters):**

**Assumption:** We execute some JavaScript code that triggers the `GetCounter` and `AddSample` functions.

**Scenario:** Let's say a JavaScript function named `myFunction` is executed multiple times, and we want to track how many times it's called.

1. **Initialization:**  The `Shell::GetCounter("myFunctionCalls", false)` is called (likely internally by V8 when instrumentation is enabled). A new `Counter` object is created and its name is set to "myFunctionCalls". The `count_` is initialized to 0.

2. **First Call to `myFunction`:** When `myFunction` is executed, the code instrumenting it (if any) might call `Shell::LookupCounter("myFunctionCalls")` to get the counter, and then `counter->AddSample(1)` is called.
   - **Input:** `sample = 1`
   - **Output:** `count_` becomes 1, `sample_total_` becomes 1.

3. **Subsequent Calls to `myFunction`:** Each subsequent execution of `myFunction` would again call `AddSample(1)`.
   - **Input:** `sample = 1`
   - **Output (after 5 calls):** `count_` becomes 5, `sample_total_` becomes 5.

**Scenario (Histogram):** Let's say we are measuring the execution time of a function in milliseconds.

1. **Initialization:** `Shell::CreateHistogram("functionExecutionTime", 0, 100, 10)` might be called. A `Counter` is created and marked as a histogram.

2. **Function Execution:** After the first execution, which took 25ms, `Shell::AddHistogramSample(histogram_object, 25)` is called.
   - **Input:** `sample = 25`
   - **Output:** `count_` becomes 1, `sample_total_` becomes 25.

3. **Another Execution:** The function takes 60ms. `Shell::AddHistogramSample(histogram_object, 60)` is called.
   - **Input:** `sample = 60`
   - **Output:** `count_` becomes 2, `sample_total_` becomes 85.

**Common Programming Errors (Related to Exception Handling):**

* **Not handling exceptions:**
   ```javascript
   // In d8:
   function mightThrow() {
     if (Math.random() > 0.5) {
       throw new Error("Random error!");
     }
     print("Function completed successfully.");
   }

   mightThrow(); // If this throws, and there's no try...catch, d8's ReportException will be invoked.
   ```
   **Error:** The program might terminate unexpectedly, and the error message will be printed by d8's exception reporting mechanism.

* **Incorrect `catch` block:**
   ```javascript
   // In d8:
   try {
     JSON.parse("invalid json");
   } catch (e) {
     console.log("Caught an error, but didn't inspect it properly.");
   }
   ```
   **Error:** While the error is caught, the `catch` block might not handle it appropriately or provide enough information for debugging. d8's reporting helps in such cases.

**归纳一下它的功能 (Summary of its functionality):**

This part of `v8/src/d8/d8.cc` is responsible for setting up a foundational runtime environment for the d8 JavaScript shell. It provides core functionalities like exception handling, performance counter tracking, basic string conversion, and the initial structure for simulating a DOM. Crucially, it defines the global object with essential functions and objects that JavaScript code running in d8 can interact with. It also handles low-level tasks like processing V8 messages, managing promise rejections, and preparing the execution context. Essentially, it's a crucial building block that enables d8 to execute JavaScript code and provides tools for monitoring and debugging that execution.

### 提示词
```
这是目录为v8/src/d8/d8.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/d8/d8.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
f("%s\n", ToCString(stack_trace));
  }
  printf("\n");
  if (enter_context) context->Exit();
}

void Shell::ReportException(v8::Isolate* isolate,
                            const v8::TryCatch& try_catch) {
  if (isolate->IsExecutionTerminating()) {
    printf("Got Execution Termination Exception\n");
  } else {
    ReportException(isolate, try_catch.Message(), try_catch.Exception());
  }
}

void Counter::Bind(const char* name, bool is_histogram) {
  base::OS::StrNCpy(name_, kMaxNameSize, name, kMaxNameSize);
  // Explicitly null-terminate, in case {name} is longer than {kMaxNameSize}.
  name_[kMaxNameSize - 1] = '\0';
  is_histogram_ = is_histogram;
}

void Counter::AddSample(int sample) {
  count_.fetch_add(1, std::memory_order_relaxed);
  sample_total_.fetch_add(sample, std::memory_order_relaxed);
}

CounterCollection::CounterCollection() {
  magic_number_ = 0xDEADFACE;
  max_counters_ = kMaxCounters;
  max_name_size_ = Counter::kMaxNameSize;
  counters_in_use_ = 0;
}

Counter* CounterCollection::GetNextCounter() {
  if (counters_in_use_ == kMaxCounters) return nullptr;
  return &counters_[counters_in_use_++];
}

void Shell::MapCounters(v8::Isolate* isolate, const char* name) {
  counters_file_ = base::OS::MemoryMappedFile::create(
      name, sizeof(CounterCollection), &local_counters_);
  void* memory =
      (counters_file_ == nullptr) ? nullptr : counters_file_->memory();
  if (memory == nullptr) {
    printf("Could not map counters file %s\n", name);
    base::OS::ExitProcess(1);
  }
  counters_ = static_cast<CounterCollection*>(memory);
  isolate->SetCounterFunction(LookupCounter);
  isolate->SetCreateHistogramFunction(CreateHistogram);
  isolate->SetAddHistogramSampleFunction(AddHistogramSample);
}

Counter* Shell::GetCounter(const char* name, bool is_histogram) {
  Counter* counter = nullptr;
  {
    base::SharedMutexGuard<base::kShared> mutex_guard(&counter_mutex_);
    auto map_entry = counter_map_->find(name);
    if (map_entry != counter_map_->end()) {
      counter = map_entry->second;
    }
  }

  if (counter == nullptr) {
    base::SharedMutexGuard<base::kExclusive> mutex_guard(&counter_mutex_);

    counter = (*counter_map_)[name];

    if (counter == nullptr) {
      counter = counters_->GetNextCounter();
      if (counter == nullptr) {
        // Too many counters.
        return nullptr;
      }
      (*counter_map_)[name] = counter;
      counter->Bind(name, is_histogram);
    }
  }

  DCHECK_EQ(is_histogram, counter->is_histogram());
  return counter;
}

int* Shell::LookupCounter(const char* name) {
  Counter* counter = GetCounter(name, false);
  return counter ? counter->ptr() : nullptr;
}

void* Shell::CreateHistogram(const char* name, int min, int max,
                             size_t buckets) {
  return GetCounter(name, true);
}

void Shell::AddHistogramSample(void* histogram, int sample) {
  Counter* counter = reinterpret_cast<Counter*>(histogram);
  counter->AddSample(sample);
}

// Turn a value into a human-readable string.
Local<String> Shell::Stringify(Isolate* isolate, Local<Value> value) {
  v8::Local<v8::Context> context =
      v8::Local<v8::Context>::New(isolate, evaluation_context_);
  if (stringify_function_.IsEmpty()) {
    Local<String> source =
        String::NewFromUtf8(isolate, stringify_source_).ToLocalChecked();
    Local<String> name = String::NewFromUtf8Literal(isolate, "d8-stringify");
    ScriptOrigin origin(name);
    Local<Script> script =
        Script::Compile(context, source, &origin).ToLocalChecked();
    stringify_function_.Reset(
        isolate, script->Run(context).ToLocalChecked().As<Function>());
  }
  Local<Function> fun = Local<Function>::New(isolate, stringify_function_);
  Local<Value> argv[1] = {value};
  v8::TryCatch try_catch(isolate);
  MaybeLocal<Value> result = fun->Call(context, Undefined(isolate), 1, argv);
  if (result.IsEmpty()) return String::Empty(isolate);
  return result.ToLocalChecked().As<String>();
}

void Shell::NodeTypeCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(i::ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();

  info.GetReturnValue().Set(v8::Number::New(isolate, 1));
}

enum class JSApiInstanceType : uint16_t {
  kGenericApiObject = 0,  // FunctionTemplateInfo::kNoJSApiObjectType.
  kEventTarget,
  kNode,
  kElement,
  kHTMLElement,
  kHTMLDivElement,
};

Local<FunctionTemplate> NewDOMFunctionTemplate(
    Isolate* isolate, JSApiInstanceType instance_type) {
  return FunctionTemplate::New(
      isolate, nullptr, Local<Value>(), Local<Signature>(), 0,
      ConstructorBehavior::kAllow, SideEffectType::kHasSideEffect, nullptr,
      static_cast<uint16_t>(instance_type));
}

Local<FunctionTemplate> Shell::CreateEventTargetTemplate(Isolate* isolate) {
  Local<FunctionTemplate> event_target =
      NewDOMFunctionTemplate(isolate, JSApiInstanceType::kEventTarget);
  return event_target;
}

Local<FunctionTemplate> Shell::CreateNodeTemplates(
    Isolate* isolate, Local<FunctionTemplate> event_target) {
  Local<FunctionTemplate> node =
      NewDOMFunctionTemplate(isolate, JSApiInstanceType::kNode);
  node->Inherit(event_target);

  PerIsolateData* data = PerIsolateData::Get(isolate);
  data->SetDomNodeCtor(node);

  Local<ObjectTemplate> proto_template = node->PrototypeTemplate();
  Local<Signature> signature = v8::Signature::New(isolate, node);
  Local<FunctionTemplate> nodeType = FunctionTemplate::New(
      isolate, NodeTypeCallback, Local<Value>(), signature, 0,
      ConstructorBehavior::kThrow, SideEffectType::kHasSideEffect, nullptr,
      static_cast<uint16_t>(JSApiInstanceType::kGenericApiObject),
      static_cast<uint16_t>(JSApiInstanceType::kElement),
      static_cast<uint16_t>(JSApiInstanceType::kHTMLDivElement));
  nodeType->SetAcceptAnyReceiver(false);
  proto_template->SetAccessorProperty(
      String::NewFromUtf8Literal(isolate, "nodeType"), nodeType);

  Local<FunctionTemplate> element =
      NewDOMFunctionTemplate(isolate, JSApiInstanceType::kElement);
  element->Inherit(node);

  Local<FunctionTemplate> html_element =
      NewDOMFunctionTemplate(isolate, JSApiInstanceType::kHTMLElement);
  html_element->Inherit(element);

  Local<FunctionTemplate> div_element =
      NewDOMFunctionTemplate(isolate, JSApiInstanceType::kHTMLDivElement);
  div_element->Inherit(html_element);

  return div_element;
}

Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
  Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
  global_template->Set(Symbol::GetToStringTag(isolate),
                       String::NewFromUtf8Literal(isolate, "global"));
  global_template->Set(isolate, "version",
                       FunctionTemplate::New(isolate, Version));

  global_template->Set(isolate, "print", FunctionTemplate::New(isolate, Print));
  global_template->Set(isolate, "printErr",
                       FunctionTemplate::New(isolate, PrintErr));
  global_template->Set(isolate, "write",
                       FunctionTemplate::New(isolate, WriteStdout));
  if (!i::v8_flags.fuzzing) {
    global_template->Set(isolate, "writeFile",
                         FunctionTemplate::New(isolate, WriteFile));
  }
  global_template->Set(isolate, "read",
                       FunctionTemplate::New(isolate, ReadFile));
  global_template->Set(isolate, "readbuffer",
                       FunctionTemplate::New(isolate, ReadBuffer));
  global_template->Set(isolate, "readline",
                       FunctionTemplate::New(isolate, ReadLine));
  global_template->Set(isolate, "load",
                       FunctionTemplate::New(isolate, ExecuteFile));
  global_template->Set(isolate, "setTimeout",
                       FunctionTemplate::New(isolate, SetTimeout));
  // Some Emscripten-generated code tries to call 'quit', which in turn would
  // call C's exit(). This would lead to memory leaks, because there is no way
  // we can terminate cleanly then, so we need a way to hide 'quit'.
  if (!options.omit_quit) {
    global_template->Set(isolate, "quit", FunctionTemplate::New(isolate, Quit));
  }
  global_template->Set(isolate, "testRunner",
                       Shell::CreateTestRunnerTemplate(isolate));
  global_template->Set(isolate, "Realm", Shell::CreateRealmTemplate(isolate));
  global_template->Set(isolate, "performance",
                       Shell::CreatePerformanceTemplate(isolate));
  global_template->Set(isolate, "Worker", Shell::CreateWorkerTemplate(isolate));

  // Prevent fuzzers from creating side effects.
  if (!i::v8_flags.fuzzing) {
    global_template->Set(isolate, "os", Shell::CreateOSTemplate(isolate));
  }
  global_template->Set(isolate, "d8", Shell::CreateD8Template(isolate));

  if (i::v8_flags.expose_async_hooks) {
    global_template->Set(isolate, "async_hooks",
                         Shell::CreateAsyncHookTemplate(isolate));
  }

  return global_template;
}

Local<ObjectTemplate> Shell::CreateOSTemplate(Isolate* isolate) {
  Local<ObjectTemplate> os_template = ObjectTemplate::New(isolate);
  AddOSMethods(isolate, os_template);
  os_template->Set(isolate, "name",
                   v8::String::NewFromUtf8Literal(isolate, V8_TARGET_OS_STRING),
                   PropertyAttribute::ReadOnly);
  os_template->Set(
      isolate, "d8Path",
      v8::String::NewFromUtf8(isolate, options.d8_path).ToLocalChecked(),
      PropertyAttribute::ReadOnly);
  return os_template;
}

Local<FunctionTemplate> Shell::CreateWorkerTemplate(Isolate* isolate) {
  Local<FunctionTemplate> worker_fun_template =
      FunctionTemplate::New(isolate, WorkerNew);
  Local<Signature> worker_signature =
      Signature::New(isolate, worker_fun_template);
  worker_fun_template->SetClassName(
      String::NewFromUtf8Literal(isolate, "Worker"));
  worker_fun_template->ReadOnlyPrototype();
  worker_fun_template->PrototypeTemplate()->Set(
      isolate, "terminate",
      FunctionTemplate::New(isolate, WorkerTerminate, Local<Value>(),
                            worker_signature));
  worker_fun_template->PrototypeTemplate()->Set(
      isolate, "terminateAndWait",
      FunctionTemplate::New(isolate, WorkerTerminateAndWait, Local<Value>(),
                            worker_signature));
  worker_fun_template->PrototypeTemplate()->Set(
      isolate, "postMessage",
      FunctionTemplate::New(isolate, WorkerPostMessage, Local<Value>(),
                            worker_signature));
  worker_fun_template->PrototypeTemplate()->Set(
      isolate, "getMessage",
      FunctionTemplate::New(isolate, WorkerGetMessage, Local<Value>(),
                            worker_signature));
  worker_fun_template->PrototypeTemplate()->SetAccessorProperty(
      String::NewFromUtf8(isolate, "onmessage", NewStringType::kInternalized)
          .ToLocalChecked(),
      FunctionTemplate::New(isolate, WorkerOnMessageGetter, Local<Value>(),
                            worker_signature),
      FunctionTemplate::New(isolate, WorkerOnMessageSetter, Local<Value>(),
                            worker_signature));
  worker_fun_template->InstanceTemplate()->SetInternalFieldCount(1);
  return worker_fun_template;
}

Local<ObjectTemplate> Shell::CreateAsyncHookTemplate(Isolate* isolate) {
  Local<ObjectTemplate> async_hooks_templ = ObjectTemplate::New(isolate);
  async_hooks_templ->Set(isolate, "createHook",
                         FunctionTemplate::New(isolate, AsyncHooksCreateHook));
  async_hooks_templ->Set(
      isolate, "executionAsyncId",
      FunctionTemplate::New(isolate, AsyncHooksExecutionAsyncId));
  async_hooks_templ->Set(
      isolate, "triggerAsyncId",
      FunctionTemplate::New(isolate, AsyncHooksTriggerAsyncId));
  return async_hooks_templ;
}

Local<ObjectTemplate> Shell::CreateTestRunnerTemplate(Isolate* isolate) {
  Local<ObjectTemplate> test_template = ObjectTemplate::New(isolate);
  // Reliable access to quit functionality. The "quit" method function
  // installed on the global object can be hidden with the --omit-quit flag
  // (e.g. on asan bots).
  test_template->Set(isolate, "quit", FunctionTemplate::New(isolate, Quit));

  return test_template;
}

Local<ObjectTemplate> Shell::CreatePerformanceTemplate(Isolate* isolate) {
  Local<ObjectTemplate> performance_template = ObjectTemplate::New(isolate);
  performance_template->Set(isolate, "now",
                            FunctionTemplate::New(isolate, PerformanceNow));
  performance_template->Set(isolate, "mark",
                            FunctionTemplate::New(isolate, PerformanceMark));
  performance_template->Set(isolate, "measure",
                            FunctionTemplate::New(isolate, PerformanceMeasure));
  performance_template->Set(
      isolate, "measureMemory",
      FunctionTemplate::New(isolate, PerformanceMeasureMemory));
  return performance_template;
}

Local<ObjectTemplate> Shell::CreateRealmTemplate(Isolate* isolate) {
  Local<ObjectTemplate> realm_template = ObjectTemplate::New(isolate);
  realm_template->Set(isolate, "current",
                      FunctionTemplate::New(isolate, RealmCurrent));
  realm_template->Set(isolate, "owner",
                      FunctionTemplate::New(isolate, RealmOwner));
  realm_template->Set(isolate, "global",
                      FunctionTemplate::New(isolate, RealmGlobal));
  realm_template->Set(isolate, "create",
                      FunctionTemplate::New(isolate, RealmCreate));
  realm_template->Set(
      isolate, "createAllowCrossRealmAccess",
      FunctionTemplate::New(isolate, RealmCreateAllowCrossRealmAccess));
  realm_template->Set(isolate, "navigate",
                      FunctionTemplate::New(isolate, RealmNavigate));
  realm_template->Set(isolate, "detachGlobal",
                      FunctionTemplate::New(isolate, RealmDetachGlobal));
  realm_template->Set(isolate, "dispose",
                      FunctionTemplate::New(isolate, RealmDispose));
  realm_template->Set(isolate, "switch",
                      FunctionTemplate::New(isolate, RealmSwitch));
  realm_template->Set(isolate, "eval",
                      FunctionTemplate::New(isolate, RealmEval));
  realm_template->SetNativeDataProperty(
      String::NewFromUtf8Literal(isolate, "shared"), RealmSharedGet,
      RealmSharedSet);
  return realm_template;
}

Local<ObjectTemplate> Shell::CreateD8Template(Isolate* isolate) {
  Local<ObjectTemplate> d8_template = ObjectTemplate::New(isolate);
  {
    Local<ObjectTemplate> file_template = ObjectTemplate::New(isolate);
    file_template->Set(isolate, "read",
                       FunctionTemplate::New(isolate, Shell::ReadFile));
    file_template->Set(isolate, "execute",
                       FunctionTemplate::New(isolate, Shell::ExecuteFile));
    d8_template->Set(isolate, "file", file_template);
  }
  {
    Local<ObjectTemplate> log_template = ObjectTemplate::New(isolate);
    log_template->Set(isolate, "getAndStop",
                      FunctionTemplate::New(isolate, LogGetAndStop));

    d8_template->Set(isolate, "log", log_template);
  }
  {
    Local<ObjectTemplate> dom_template = ObjectTemplate::New(isolate);
    Local<FunctionTemplate> event_target =
        Shell::CreateEventTargetTemplate(isolate);
    dom_template->Set(isolate, "EventTarget", event_target);
    dom_template->Set(isolate, "Div",
                      Shell::CreateNodeTemplates(isolate, event_target));
    d8_template->Set(isolate, "dom", dom_template);
  }
  {
    Local<ObjectTemplate> test_template = ObjectTemplate::New(isolate);
    // For different runs of correctness fuzzing the bytecode of a function
    // might get flushed, resulting in spurious errors.
    if (!i::v8_flags.correctness_fuzzer_suppressions) {
      test_template->Set(
          isolate, "verifySourcePositions",
          FunctionTemplate::New(isolate, TestVerifySourcePositions));
    }
    // Correctness fuzzing will attempt to compare results of tests with and
    // without turbo_fast_api_calls, so we don't expose the fast_c_api
    // constructor when --correctness_fuzzer_suppressions is on.
    if (options.expose_fast_api && i::v8_flags.turbo_fast_api_calls &&
        !i::v8_flags.correctness_fuzzer_suppressions) {
      test_template->Set(isolate, "FastCAPI",
                         Shell::CreateTestFastCApiTemplate(isolate));
      test_template->Set(isolate, "LeafInterfaceType",
                         Shell::CreateLeafInterfaceTypeTemplate(isolate));
    }
    // Allows testing code paths that are triggered when Origin Trials are
    // added in the browser.
    test_template->Set(
        isolate, "installConditionalFeatures",
        FunctionTemplate::New(isolate, Shell::InstallConditionalFeatures));

    // Enable JavaScript Promise Integration at runtime, to simulate
    // Origin Trial behavior.
    test_template->Set(isolate, "enableJSPI",
                       FunctionTemplate::New(isolate, Shell::EnableJSPI));

    d8_template->Set(isolate, "test", test_template);
  }
  {
    Local<ObjectTemplate> promise_template = ObjectTemplate::New(isolate);
    promise_template->Set(
        isolate, "setHooks",
        FunctionTemplate::New(isolate, SetPromiseHooks, Local<Value>(),
                              Local<Signature>(), 4));
    d8_template->Set(isolate, "promise", promise_template);
  }
  {
    Local<ObjectTemplate> debugger_template = ObjectTemplate::New(isolate);
    debugger_template->Set(
        isolate, "enable",
        FunctionTemplate::New(isolate, EnableDebugger, Local<Value>(),
                              Local<Signature>(), 0));
    debugger_template->Set(
        isolate, "disable",
        FunctionTemplate::New(isolate, DisableDebugger, Local<Value>(),
                              Local<Signature>(), 0));
    d8_template->Set(isolate, "debugger", debugger_template);
  }
  {
    Local<ObjectTemplate> serializer_template = ObjectTemplate::New(isolate);
    serializer_template->Set(
        isolate, "serialize",
        FunctionTemplate::New(isolate, SerializerSerialize));
    serializer_template->Set(
        isolate, "deserialize",
        FunctionTemplate::New(isolate, SerializerDeserialize, Local<Value>(),
                              Local<Signature>(), 1));
    d8_template->Set(isolate, "serializer", serializer_template);
  }
  {
    Local<ObjectTemplate> profiler_template = ObjectTemplate::New(isolate);
    profiler_template->Set(
        isolate, "setOnProfileEndListener",
        FunctionTemplate::New(isolate, ProfilerSetOnProfileEndListener));
    profiler_template->Set(
        isolate, "triggerSample",
        FunctionTemplate::New(isolate, ProfilerTriggerSample));
    d8_template->Set(isolate, "profiler", profiler_template);
  }
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  d8_template->Set(
      isolate, "getContinuationPreservedEmbedderDataViaAPIForTesting",
      FunctionTemplate::New(isolate, GetContinuationPreservedEmbedderData));
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  d8_template->Set(isolate, "terminate",
                   FunctionTemplate::New(isolate, Terminate));
  d8_template->Set(isolate, "getExtrasBindingObject",
                   FunctionTemplate::New(isolate, GetExtrasBindingObject));
  if (!options.omit_quit) {
    d8_template->Set(isolate, "quit", FunctionTemplate::New(isolate, Quit));
  }
  return d8_template;
}

static void PrintMessageCallback(Local<Message> message, Local<Value> error) {
  switch (message->ErrorLevel()) {
    case v8::Isolate::kMessageWarning:
    case v8::Isolate::kMessageLog:
    case v8::Isolate::kMessageInfo:
    case v8::Isolate::kMessageDebug: {
      break;
    }

    case v8::Isolate::kMessageError: {
      Shell::ReportException(message->GetIsolate(), message, error);
      return;
    }

    default: {
      UNREACHABLE();
    }
  }
  // Converts a V8 value to a C string.
  auto ToCString = [](const v8::String::Utf8Value& value) {
    return *value ? *value : "<string conversion failed>";
  };
  Isolate* isolate = message->GetIsolate();
  v8::String::Utf8Value msg(isolate, message->Get());
  const char* msg_string = ToCString(msg);
  // Print (filename):(line number): (message).
  v8::String::Utf8Value filename(isolate,
                                 message->GetScriptOrigin().ResourceName());
  const char* filename_string = ToCString(filename);
  Maybe<int> maybeline = message->GetLineNumber(isolate->GetCurrentContext());
  int linenum = maybeline.IsJust() ? maybeline.FromJust() : -1;
  printf("%s:%i: %s\n", filename_string, linenum, msg_string);
}

void Shell::PromiseRejectCallback(v8::PromiseRejectMessage data) {
  if (options.ignore_unhandled_promises) return;
  if (data.GetEvent() == v8::kPromiseRejectAfterResolved ||
      data.GetEvent() == v8::kPromiseResolveAfterResolved) {
    // Ignore reject/resolve after resolved.
    return;
  }
  v8::Local<v8::Promise> promise = data.GetPromise();
  v8::Isolate* isolate = promise->GetIsolate();
  PerIsolateData* isolate_data = PerIsolateData::Get(isolate);

  if (data.GetEvent() == v8::kPromiseHandlerAddedAfterReject) {
    isolate_data->RemoveUnhandledPromise(promise);
    return;
  }

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  bool capture_exceptions =
      i_isolate->get_capture_stack_trace_for_uncaught_exceptions();
  isolate->SetCaptureStackTraceForUncaughtExceptions(true);
  v8::Local<Value> exception = data.GetValue();
  v8::Local<Message> message;
  // Assume that all objects are stack-traces.
  if (exception->IsObject()) {
    message = v8::Exception::CreateMessage(isolate, exception);
  }
  if (!exception->IsNativeError() &&
      (message.IsEmpty() || message->GetStackTrace().IsEmpty())) {
    // If there is no real Error object, manually create a stack trace.
    exception = v8::Exception::Error(
        v8::String::NewFromUtf8Literal(isolate, "Unhandled Promise."));
    message = Exception::CreateMessage(isolate, exception);
  }
  isolate->SetCaptureStackTraceForUncaughtExceptions(capture_exceptions);

  isolate_data->AddUnhandledPromise(promise, message, exception);
}

void Shell::Initialize(Isolate* isolate, D8Console* console,
                       bool isOnMainThread) {
  isolate->SetPromiseRejectCallback(PromiseRejectCallback);
  isolate->SetWasmAsyncResolvePromiseCallback(
      D8WasmAsyncResolvePromiseCallback);
  if (isOnMainThread) {
    // Set up counters
    if (i::v8_flags.map_counters[0] != '\0') {
      MapCounters(isolate, i::v8_flags.map_counters);
    }
    // Disable default message reporting.
    isolate->AddMessageListenerWithErrorLevel(
        PrintMessageCallback,
        v8::Isolate::kMessageError | v8::Isolate::kMessageWarning |
            v8::Isolate::kMessageInfo | v8::Isolate::kMessageDebug |
            v8::Isolate::kMessageLog);
  }

  isolate->SetHostImportModuleDynamicallyCallback(
      Shell::HostImportModuleDynamically);
  isolate->SetHostImportModuleWithPhaseDynamicallyCallback(
      Shell::HostImportModuleWithPhaseDynamically);
  isolate->SetHostInitializeImportMetaObjectCallback(
      Shell::HostInitializeImportMetaObject);
  isolate->SetHostCreateShadowRealmContextCallback(
      Shell::HostCreateShadowRealmContext);

  debug::SetConsoleDelegate(isolate, console);
}

Local<String> Shell::WasmLoadSourceMapCallback(Isolate* isolate,
                                               const char* path) {
  return Shell::ReadFile(isolate, path, false).ToLocalChecked();
}

MaybeLocal<Context> Shell::CreateEvaluationContext(Isolate* isolate) {
  // This needs to be a critical section since this is not thread-safe
  i::ParkedMutexGuard lock_guard(
      reinterpret_cast<i::Isolate*>(isolate)->main_thread_local_isolate(),
      context_mutex_.Pointer());
  // Initialize the global objects
  Local<ObjectTemplate> global_template = CreateGlobalTemplate(isolate);
  EscapableHandleScope handle_scope(isolate);
  Local<Context> context = Context::New(isolate, nullptr, global_template);
  if (context.IsEmpty()) {
    DCHECK(isolate->IsExecutionTerminating());
    return {};
  }
  if (i::v8_flags.perf_prof_annotate_wasm ||
      i::v8_flags.vtune_prof_annotate_wasm) {
    isolate->SetWasmLoadSourceMapCallback(Shell::WasmLoadSourceMapCallback);
  }
  InitializeModuleEmbedderData(context);
  Context::Scope scope(context);
  if (options.include_arguments) {
    const std::vector<const char*>& args = options.arguments;
    int size = static_cast<int>(args.size());
    Local<Array> array = Array::New(isolate, size);
    for (int i = 0; i < size; i++) {
      Local<String> arg =
          v8::String::NewFromUtf8(isolate, args[i]).ToLocalChecked();
      Local<Number> index = v8::Number::New(isolate, i);
      array->Set(context, index, arg).FromJust();
    }
    Local<String> name = String::NewFromUtf8Literal(
        isolate, "arguments", NewStringType::kInternalized);
    context->Global()->Set(context, name, array).FromJust();
  }
  {
    // setup console global.
    Local<String> name = String::NewFromUtf8Literal(
        isolate, "console", NewStringType::kInternalized);
    Local<Value> console =
        context->GetExtrasBindingObject()->Get(context, name).ToLocalChecked();
    context->Global()->Set(context, name, console).FromJust();
  }

  return handle_scope.Escape(context);
}

void Shell::WriteIgnitionDispatchCountersFile(v8::Isolate* isolate) {
  HandleScope handle_scope(isolate);
  Local<Context> context = Context::New(isolate);
  Context::Scope context_scope(context);

  i::Handle<i::JSObject> dispatch_counters =
      reinterpret_cast<i::Isolate*>(isolate)
          ->interpreter()
          ->GetDispatchCountersObject();
  std::ofstream dispatch_counters_stream(
      i::v8_flags.trace_ignition_dispatches_output_file);
  dispatch_counters_stream << *String::Utf8Value(
      isolate, JSON::Stringify(context, Utils::ToLocal(dispatch_counters))
                   .ToLocalChecked());
}

namespace {
int LineFromOffset(Local<debug::Script> script, int offset) {
  debug::Location location = script->GetSourceLocation(offset);
  return location.GetLineNumber();
}

void WriteLcovDataForRange(std::vector<uint32_t>* lines, int start_line,
                           int end_line, uint32_t count) {
  // Ensure space in the array.
  lines->resize(std::max(static_cast<size_t>(end_line + 1), lines->size()), 0);
  // Boundary lines could be shared between two functions with different
  // invocation counts. Take the maximum.
  (*lines)[start_line] = std::max((*lines)[start_line], count);
  (*lines)[end_line] = std::max((*lines)[end_line], count);
  // Invocation counts for non-boundary lines are overwritten.
  for (int k = start_line + 1; k < end_line; k++) (*lines)[k] = count;
}

void WriteLcovDataForNamedRange(std::ostream& sink,
                                std::vector<uint32_t>* lines,
                                const std::string& name, int start_line,
                                int end_line, uint32_t count) {
  WriteLcovDataForRange(lines, start_line, end_line, count);
  sink << "FN:" << start_line + 1 << "," << name << std::endl;
  sink << "FNDA:" << count << "," << name << std::endl;
}
}  // namespace

// Write coverage data in LCOV format. See man page for geninfo(1).
void Shell::WriteLcovData(v8::Isolate* isolate, const char* file) {
  if (!file) return;
  HandleScope handle_scope(isolate);
  debug::Coverage coverage = debug::Coverage::CollectPrecise(isolate);
  std::ofstream sink(file, std::ofstream::app);
  for (size_t i = 0; i < coverage.ScriptCount(); i++) {
    debug::Coverage::ScriptData script_data = coverage.GetScriptData(i);
    Local<debug::Script> script = script_data.GetScript();
    // Skip unnamed scripts.
    Local<String> name;
    if (!script->Name().ToLocal(&name)) continue;
    std::string file_name = ToSTLString(isolate, name);
    // Skip scripts not backed by a file.
    if (!std::ifstream(file_name).good()) continue;
    sink << "SF:";
    sink << NormalizePath(file_name, GetWorkingDirectory()) << std::endl;
    std::vector<uint32_t> lines;
    for (size_t j = 0; j < script_data.FunctionCount(); j++) {
      debug::Coverage::FunctionData function_data =
          script_data.GetFunctionData(j);

      // Write function stats.
      {
        debug::Location start =
            script->GetSourceLocation(function_data.StartOffset());
        debug::Location end =
            script->GetSourceLocation(function_data.EndOffset());
        int start_line = start.GetLineNumber();
        int end_line = end.GetLineNumber();
        uint32_t count = function_data.Count();

        Local<String> function_name;
        std::stringstream name_stream;
        if (function_data.Name().ToLocal(&function_name)) {
          name_stream << ToSTLString(isolate, function_name);
        } else {
          name_stream << "<" << start_line + 1 << "-";
          name_stream << start.GetColumnNumber() << ">";
        }

        WriteLcovDataForNamedRange(sink, &lines, name_stream.str(), start_line,
                                   end_line, count);
      }

      // Process inner blocks.
      for (size_t k = 0; k < function_data.BlockCount(); k++) {
        debug::Coverage::BlockData block_data = function_data.GetBlockData(k);
        int start_line = LineFromOffset(script, block_data.StartOffset());
        int end_line = LineFromOffset(script, block_data.EndOffset() - 1);
        uint32_t count = block_data.Count();
        WriteLcovDataForRange(&lines, start_line, end_line, count);
      }
    }
    // Write per-line coverage. LCOV uses 1-based line numbers.
    for (size_t j = 0; j < lines.size(); j++) {
      sink << "DA:" << (j + 1) << "," << lines[j] << std::endl;
    }
    sink << "end_of_record" << std::endl;
  }
}

void Shell::OnExit(v8::Isolate* isolate, bool dispose) {
  platform::NotifyIsolateShutdown(g_default_platform, isolate);

  if (Worker* worker = Worker::GetCurrentWorker()) {
    // When invoking `quit` on a worker isolate, the worker needs to reach
    // State::kTerminated before invoking Isolate::Dispose. This is because the
    // main thread tries to terminate all workers at the end, which can happen
    // concurrently to Isolate::Dispose.
    worker->EnterTerminatedState();
  }

  if (dispose) {
    isolate->Dispose();
  } else {
    // Normally, Dispose() prints counters. Benchmarks expect counters to be
    // printed on process exit, so do so manually if not disposing.
    isolate->DumpAndResetStats();
  }

  // Simulate errors before disposing V8, as that resets flags (via
  // FlagList::ResetAllFlags()), but error simulation reads the random seed.
  if (options.simulate_errors && is_valid_fuzz_script()) {
    // Simulate several errors detectable by fuzzers behind a flag if the
    // minimum file size for fuzzing was executed.
    FuzzerMonitor::SimulateErrors();
  }

  if (dispose) {
    V8::Dispose();
    V8::DisposePlatform();
  }

  if (options.dump_counters || options.dump_counters_nvp) {
    base::SharedMutexGuard<base::kShared> mutex_guard(&counter_mutex_);
    std::vector<std::pair<std::string, Counter*>> counters(
        counter_map_->begin(), counter_map_->end());
    std::sort(counters.begin(), counters.end());

    if (options.dump_counters_nvp) {
      // Dump counters as name-value pairs.
      for (const auto& pair : counters) {
        std::string key = pair.first;
        Counter* counter = pair.second;
        if (counter->is_histogram()) {
          std::cout << "\"c:" << key << "\"=" << counter->count() << "\n";
          std::cout << "\"t:" << key << "\"=" << counter->sample_total()
                    << "\n";
        } else {
          std::cout << "\"" << key << "\"=" << counter->count() << "\n";
        }
      }
    } else {
      // Dump counters in formatted boxes.
      constexpr int kNameBoxSize = 64;
      constexpr int kValueBoxSize = 13;
      std::cout << "+" << std::string(kNameBoxSize, '-') << "+"
                << std::string(kValueBoxSize, '-') << "+\n";
      std::cout << "| Name" << std::string(kNameBoxSize - 5, ' ') << "| Value"
                << std::string(kValueBoxSize - 6, ' ') << "|\n";
      std::cout << "+" << std::string(kNameBoxSize, '-') << "+"
                << std::string(kValueBoxSize, '-') << "+\n";
      for (const auto& pair : counters) {
        std::string key = pair.first;
        Counter* counter = pair.second;
        if (counter->is_histogram()) {
          std::cout << "| c:" << std::setw(kNameBoxSize - 4) << std::left << key
                    << " | " << std::setw(kValueBoxSize - 2) << std::right
                    << counter->count() << " |\n";
          std::cout << "| t:" << std::setw(kNameBoxSize - 4) << std::left << key
                    << " | " << std::setw(kValueBoxSize - 2) << std::right
                    << counter->sample_total() << " |\n";
        }
```