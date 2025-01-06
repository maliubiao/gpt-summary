Response:
Let's break down the thought process to analyze this C++ V8 unittest file.

**1. Initial Scan and Overall Purpose:**

The file name `code-pages-unittest.cc` immediately suggests it's testing the "code pages" functionality in V8. The `#include` directives confirm this, referencing `code-desc.h`, `globals.h`, `isolate.h`, `handles-inl.h`, `heap/factory.h`, `heap/spaces.h`, and `libsampler/sampler.h`. These are all core V8 components related to code generation, memory management, and sampling. The `testing/gtest/include/gtest/gtest.h` inclusion indicates the use of the Google Test framework.

**2. Understanding the "Code Pages" Concept:**

Even without deep V8 knowledge, the term "code pages" implies memory regions specifically for storing compiled code. The comments at the beginning of several test functions (`CodeRangeCorrectContents`, `CodePagesCorrectContents`) hint at different levels of support for this feature across architectures. This likely relates to how V8 manages executable memory permissions and organization.

**3. Analyzing the Helper Functions:**

* `getFooCode(int n)`: This function generates JavaScript code dynamically. It creates a function named `fooN` (where N is an integer) and prepares it for optimization using V8's internal syntax (`%%PrepareFunctionForOptimization`, `%%OptimizeFunctionOnNextCall`). This signals that the tests are likely focused on how optimized code is handled.
* `PagesHasExactPage`, `PagesContainsRange`, `PagesContainsAddress`: These helper functions are crucial. They examine a `std::vector<MemoryRange>` (presumably representing the "code pages") and check for the presence of specific memory regions or addresses. This strongly suggests the core functionality being tested is the correctness of the reported code pages.

**4. Examining Individual Test Cases:**

* **`CodeRangeCorrectContents`:**  The `if (!i_isolate()->RequiresCodeRange()) return;` line indicates this test is specific to architectures that have a "code range." It checks if the reported code pages contain the main code region and the embedded blob code.
* **`CodePagesCorrectContents`:**  The `if (!kHaveCodePages) return;` and the check for `code_region.is_empty()` suggest this test focuses on architectures with distinct "code pages" rather than a single "code range." It verifies the presence of the embedded blob code even without a regular code range.
* **`OptimizedCodeWithCodeRange` and `OptimizedCodeWithCodePages`:** These tests compile and optimize JavaScript code. They then verify that the generated optimized code's memory address falls within the reported code pages. This confirms that the code page tracking works for dynamically generated code.
* **`LargeCodeObject`:** This test creates a very large code object that is expected to be allocated in a special "CODE_LO_SPACE."  It verifies that this large object is correctly tracked in the code pages and that its removal via garbage collection is also reflected in the code page information.
* **`LargeCodeObjectWithSignalHandler`:** This is a more complex test involving a separate thread (`SamplingThread`) and a signal handler (`SignalSender`). It aims to verify the thread-safety and correctness of code page reporting even when a signal handler is active and potentially accessing the code page information concurrently.
* **`Sorted`:** This test creates multiple large code objects and then deletes one. It verifies that the list of code pages remains sorted by starting address, which is important for efficient searching and management of these memory regions.

**5. Identifying Key Concepts and Potential Issues:**

Based on the tests, the core concepts being validated are:

* **Code Range/Code Pages:** The fundamental mechanism for organizing and tracking executable memory.
* **Embedded Blob Code:**  Pre-compiled code included within the V8 binary.
* **Optimized Code:**  Code generated by V8's optimizing compilers (Turbofan/Maglev).
* **CODE_LO_SPACE:** A special memory space for large code objects.
* **Garbage Collection (GC):** How V8 reclaims unused memory, including code pages.
* **Signal Handling and Threading:** Ensuring code page information is consistent even with concurrent access.
* **Sorting:** Maintaining the order of code pages for efficiency.

Potential user programming errors are less directly tested here, but the tests implicitly guard against:

* **Memory corruption:** Incorrect code page tracking could lead to V8 trying to execute data or vice-versa.
* **Security vulnerabilities:** Incorrect memory permissions could be a security risk.
* **Performance issues:** Inefficient code page management could slow down code execution or garbage collection.

**6. Formulating the JavaScript Examples (Constraint 3):**

The `getFooCode` function gives a clear example of the JavaScript being used. The key is to show how V8's optimization process is triggered.

**7. Formulating the Input/Output (Constraint 4):**

For the simpler tests, the input is essentially the initial state of the V8 isolate. The output is the state of the code pages *after* some action (like compiling code or triggering GC). For more complex tests like `LargeCodeObject`, the creation and deletion of the large code object are the inputs, and the presence or absence of its memory region in the code pages is the output.

**8. Formulating the Common Programming Errors (Constraint 5):**

Think about what could go wrong *if* the code page mechanism wasn't working correctly. Accessing freed memory, executing data, etc. are good candidates.

**Self-Correction/Refinement:**

During the analysis, I might initially focus too much on the C++ details. It's important to step back and understand the *purpose* of each test. The helper functions are key to understanding what properties of the code pages are being verified. Realizing that the tests cover different architectures and scenarios (`CodeRange` vs. `CodePages`) is also important for a complete understanding. Similarly, recognizing the connection between JavaScript code (via `getFooCode`) and the underlying memory management is crucial.
`v8/test/unittests/codegen/code-pages-unittest.cc` is a C++ unit test file for the V8 JavaScript engine. Its primary function is to verify the correctness of the **code pages** mechanism within V8's code generation and memory management.

Here's a breakdown of its functionalities:

**Core Functionality Under Test: Code Pages**

The concept of "code pages" in V8 refers to how V8 manages memory regions where compiled JavaScript code is stored. This is crucial for security (marking memory as executable) and potentially for performance and memory organization. The tests in this file specifically check:

* **Existence and Contents of Code Ranges/Pages:**  Verifying that the expected memory ranges or pages allocated for code exist and contain the correct segments, like the main code region and the embedded built-in code. The behavior might differ based on the target architecture (some have a single "code range," others have finer-grained "code pages").
* **Tracking of Optimized Code:** Ensuring that when JavaScript functions are optimized (using Turbofan or Maglev), the generated machine code is placed within the designated code pages and that these pages are correctly recorded.
* **Handling of Large Code Objects:** Testing how V8 manages very large compiled code chunks that might require separate allocation strategies (like `CODE_LO_SPACE`) and confirming they are also tracked within the code page system.
* **Garbage Collection and Code Pages:** Verifying that when code objects are no longer needed and are garbage collected, the corresponding code pages are correctly updated and potentially removed from the tracked list.
* **Interaction with Signal Handlers:** Checking the thread-safety of accessing code page information, especially when signal handlers (used for profiling or debugging) might be active concurrently.
* **Order of Code Pages:**  Ensuring that the reported list of code pages is sorted, which can be important for efficient lookup and management.

**Is it a Torque Source?**

The filename ends with `.cc`, which is the standard extension for C++ source files. Therefore, `v8/test/unittests/codegen/code-pages-unittest.cc` is **not** a V8 Torque source file. Torque files typically have the `.tq` extension.

**Relationship with JavaScript and Examples**

This C++ unittest directly relates to the execution of JavaScript code within V8. The tests compile and run JavaScript snippets to trigger code generation and optimization, then inspect the underlying memory management of the generated code.

Here are JavaScript examples illustrating the concepts being tested:

```javascript
// Example related to optimized code placement (similar to OptimizedCodeWithCodeRange/Pages tests)
function foo(a, b) {
  let x = a * b;
  let y = x ^ b;
  let z = y / a;
  return x + y - z;
}

// Trigger optimization
%PrepareFunctionForOptimization(foo);
foo(1, 2);
foo(1, 2);
%OptimizeFunctionOnNextCall(foo);
foo(1, 2); // Optimized code is now generated and should reside in a code page
```

```javascript
// Example related to large code objects (similar to LargeCodeObject test)
// (This is a simplified conceptual example, creating truly large functions programmatically can be complex)
function createLargeFunction() {
  let code = "function longFunction() { ";
  for (let i = 0; i < 10000; i++) {
    code += " let x" + i + " = " + i + ";";
  }
  code += " return 0; }";
  eval(code); // Note: eval is generally discouraged, used here for illustration
  return longFunction;
}

let largeFunc = createLargeFunction();
largeFunc(); // The code for largeFunc might be placed in a special code space
```

**Code Logic Reasoning and Examples**

Let's consider the `OptimizedCodeWithCodePages` test case.

**Assumptions:**

1. V8 is running on an architecture where `kHaveCodePages` is true (e.g., ARM32).
2. Turbofan or Maglev is enabled for optimization.

**Input:**

* A JavaScript function `fooN` defined in the test.
* V8 internal functions `%%PrepareFunctionForOptimization` and `%%OptimizeFunctionOnNextCall` are used.

**Code Logic:**

The test repeatedly defines and optimizes different versions of the `foo` function (e.g., `foo0`, `foo1`, etc.). The key logic is to:

1. **Compile and Optimize:** Force V8 to compile and optimize the JavaScript function.
2. **Get Code Location:** Retrieve the memory address of the generated optimized machine code (`foo->code(i_isolate())->instruction_stream()->address()`).
3. **Check Code Page Membership:**  Verify that this memory address falls within one of the memory ranges reported by `i_isolate()->GetCodePages()`.
4. **Track New Pages:** The test specifically looks for the creation of new code pages as more optimized functions are generated.
5. **Garbage Collection:** After creating several optimized functions and observing a new code page being created, the test removes references to these functions and triggers garbage collection.
6. **Verify Page Removal:** It then checks that the newly created code page is no longer present in the list of code pages.

**Example of Expected Input and Output (Simplified):**

Imagine the code pages before running the `OptimizedCodeWithCodePages` test:

```
[
  { start: 0x1000, length_in_bytes: 4096 }, // Embedded code
  // ... other initial code pages
]
```

After running the test and generating several optimized `foo` functions, a new code page might be created:

```
[
  { start: 0x1000, length_in_bytes: 4096 },
  // ... other initial code pages
  { start: 0x8000, length_in_bytes: 4096 }  // New code page for optimized functions
]
```

After garbage collection, if the optimized functions are no longer reachable, the new code page might be removed:

```
[
  { start: 0x1000, length_in_bytes: 4096 },
  // ... other initial code pages
]
```

**Common Programming Errors (Implicitly Tested)**

While this unittest doesn't directly test *user* programming errors, it implicitly guards against potential errors in V8's code generation and memory management that *could* be caused by user code or V8 bugs. Here are some examples of errors this unittest helps to prevent:

1. **Memory Corruption:** If V8 incorrectly manages code pages, it could potentially write data into memory marked as executable or vice-versa, leading to crashes or security vulnerabilities. The tests that check the contents and boundaries of code pages help prevent this.

2. **Incorrect Code Execution:** If the generated machine code is not placed in executable memory regions, the program will crash or behave unexpectedly. The tests verifying the placement of optimized code are crucial here.

3. **Memory Leaks:** If V8 fails to track and release code pages after the corresponding code is no longer needed, it could lead to memory leaks. The garbage collection tests are designed to detect such leaks in the code page management.

4. **Security Vulnerabilities (Execution of Data):** A critical security concern is the ability for attackers to inject code and have it executed. The code page mechanism, by enforcing clear boundaries between code and data, helps mitigate this. The tests implicitly validate this separation.

5. **Race Conditions in Concurrent Access:** The `LargeCodeObjectWithSignalHandler` test specifically addresses the potential for race conditions when multiple threads (including signal handlers) are accessing code page information simultaneously. This is vital for the stability of V8 in multithreaded environments.

In summary, `v8/test/unittests/codegen/code-pages-unittest.cc` is a vital part of V8's testing infrastructure, ensuring the correct and safe management of memory used for storing and executing JavaScript code. It focuses on the internal mechanisms of V8 and indirectly protects against various potential errors that could arise during JavaScript execution.

Prompt: 
```
这是目录为v8/test/unittests/codegen/code-pages-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/codegen/code-pages-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "src/codegen/code-desc.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/handles/handles-inl.h"
#include "src/heap/factory.h"
#include "src/heap/spaces.h"
#include "src/libsampler/sampler.h"
#include "test/unittests/heap/heap-utils.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {

using CodePagesTest = TestWithContext;

namespace internal {
namespace test_code_pages {

// We have three levels of support which have different behaviors to test.
// 1 - Have code range. ARM64 and x64
// 2 - Have code pages. ARM32 only
// 3 - Nothing - This feature does not work on other platforms.
#if defined(V8_TARGET_ARCH_ARM)
static const bool kHaveCodePages = true;
#else
static const bool kHaveCodePages = false;
#endif  // defined(V8_TARGET_ARCH_ARM)

static const char* foo_source = R"(
  function foo%d(a, b) {
    let x = a * b;
    let y = x ^ b;
    let z = y / a;
    return x + y - z;
  };
  %%PrepareFunctionForOptimization(foo%d);
  foo%d(1, 2);
  foo%d(1, 2);
  %%OptimizeFunctionOnNextCall(foo%d);
  foo%d(1, 2);
)";

std::string getFooCode(int n) {
  constexpr size_t kMaxSize = 512;
  char foo_replaced[kMaxSize];
  EXPECT_LE(n, 999999);
  snprintf(foo_replaced, kMaxSize, foo_source, n, n, n, n, n, n);

  return std::string(foo_replaced);
}

namespace {

bool PagesHasExactPage(std::vector<MemoryRange>* pages, Address search_page) {
  void* addr = reinterpret_cast<void*>(search_page);
  auto it =
      std::find_if(pages->begin(), pages->end(),
                   [addr](const MemoryRange& r) { return r.start == addr; });
  return it != pages->end();
}

bool PagesHasExactPage(std::vector<MemoryRange>* pages, Address search_page,
                       size_t size) {
  void* addr = reinterpret_cast<void*>(search_page);
  auto it = std::find_if(pages->begin(), pages->end(),
                         [addr, size](const MemoryRange& r) {
                           return r.start == addr && r.length_in_bytes == size;
                         });
  return it != pages->end();
}

bool PagesContainsRange(std::vector<MemoryRange>* pages, Address search_address,
                        size_t size) {
  uint8_t* addr = reinterpret_cast<uint8_t*>(search_address);
  auto it =
      std::find_if(pages->begin(), pages->end(), [=](const MemoryRange& r) {
        const uint8_t* page_start = reinterpret_cast<const uint8_t*>(r.start);
        const uint8_t* page_end = page_start + r.length_in_bytes;
        return addr >= page_start && (addr + size) <= page_end;
      });
  return it != pages->end();
}

bool PagesContainsAddress(std::vector<MemoryRange>* pages,
                          Address search_address) {
  return PagesContainsRange(pages, search_address, 0);
}

}  // namespace

TEST_F(CodePagesTest, CodeRangeCorrectContents) {
  if (!i_isolate()->RequiresCodeRange()) return;

  std::vector<MemoryRange>* pages = i_isolate()->GetCodePages();

  const base::AddressRegion& code_region = i_isolate()->heap()->code_region();
  EXPECT_TRUE(!code_region.is_empty());
  // We should only have the code range and the embedded code range.
  EXPECT_EQ(2u, pages->size());
  EXPECT_TRUE(
      PagesHasExactPage(pages, code_region.begin(), code_region.size()));
  EXPECT_TRUE(PagesHasExactPage(
      pages, reinterpret_cast<Address>(i_isolate()->CurrentEmbeddedBlobCode()),
      i_isolate()->CurrentEmbeddedBlobCodeSize()));
  if (i_isolate()->is_short_builtin_calls_enabled()) {
    // In this case embedded blob code must be included via code_region.
    EXPECT_TRUE(PagesContainsRange(
        pages, reinterpret_cast<Address>(i_isolate()->embedded_blob_code()),
        i_isolate()->embedded_blob_code_size()));
  } else {
    EXPECT_TRUE(PagesHasExactPage(
        pages, reinterpret_cast<Address>(i_isolate()->embedded_blob_code()),
        i_isolate()->embedded_blob_code_size()));
  }
}

TEST_F(CodePagesTest, CodePagesCorrectContents) {
  if (!kHaveCodePages) return;

  std::vector<MemoryRange>* pages = i_isolate()->GetCodePages();
  // There might be other pages already.
  EXPECT_GE(pages->size(), 1u);

  const base::AddressRegion& code_region = i_isolate()->heap()->code_region();
  EXPECT_TRUE(code_region.is_empty());

  // We should have the embedded code range even when there is no regular code
  // range.
  EXPECT_TRUE(PagesHasExactPage(
      pages, reinterpret_cast<Address>(i_isolate()->embedded_blob_code()),
      i_isolate()->embedded_blob_code_size()));
}

TEST_F(CodePagesTest, OptimizedCodeWithCodeRange) {
  v8_flags.allow_natives_syntax = true;
  if (!i_isolate()->RequiresCodeRange()) return;

  HandleScope scope(i_isolate());

  std::string foo_str = getFooCode(1);
  RunJS(foo_str.c_str());
  v8::Local<v8::Function> local_foo = v8::Local<v8::Function>::Cast(
      context()->Global()->Get(context(), NewString("foo1")).ToLocalChecked());
  DirectHandle<JSFunction> foo =
      Cast<JSFunction>(v8::Utils::OpenDirectHandle(*local_foo));

  Tagged<Code> code = foo->code(i_isolate());
  // We don't produce optimized code when run with --no-turbofan and
  // --no-maglev.
  if (!code->is_optimized_code()) return;
  Tagged<InstructionStream> foo_code = code->instruction_stream();

  EXPECT_TRUE(i_isolate()->heap()->InSpace(foo_code, CODE_SPACE));

  std::vector<MemoryRange>* pages = i_isolate()->GetCodePages();
  EXPECT_TRUE(PagesContainsAddress(pages, foo_code.address()));
}

TEST_F(CodePagesTest, OptimizedCodeWithCodePages) {
  if (!kHaveCodePages) return;
  // We don't want incremental marking to start which could cause the code to
  // not be collected on the CollectGarbage() call.
  ManualGCScope manual_gc_scope(i_isolate());
  v8_flags.allow_natives_syntax = true;

  const void* created_page = nullptr;
  int num_foos_created = 0;

  {
    HandleScope scope(i_isolate());

    size_t num_code_pages = 0;
    size_t initial_num_code_pages = 0;

    // Keep generating new code until a new code page is added to the list.
    for (int n = 0; n < 999999; n++) {
      // Compile and optimize the code and get a reference to it.
      std::string foo_str = getFooCode(n);
      char foo_name[10];
      snprintf(foo_name, sizeof(foo_name), "foo%d", n);
      RunJS(foo_str.c_str());
      v8::Local<v8::Function> local_foo = v8::Local<v8::Function>::Cast(
          context()
              ->Global()
              ->Get(context(), NewString(foo_name))
              .ToLocalChecked());
      DirectHandle<JSFunction> foo =
          Cast<JSFunction>(v8::Utils::OpenDirectHandle(*local_foo));

      // If there is baseline code, check that it's only due to
      // --always-sparkplug (if this check fails, we'll have to re-think this
      // test).
      if (foo->shared()->HasBaselineCode()) {
        EXPECT_TRUE(v8_flags.always_sparkplug);
        return;
      }
      Tagged<Code> code = foo->code(i_isolate());
      // We don't produce optimized code when run with --no-turbofan and
      // --no-maglev.
      if (!code->is_optimized_code()) return;
      Tagged<InstructionStream> foo_code = code->instruction_stream();

      EXPECT_TRUE(i_isolate()->heap()->InSpace(foo_code, CODE_SPACE));

      // Check that the generated code ended up in one of the code pages
      // returned by GetCodePages().
      uint8_t* foo_code_ptr = reinterpret_cast<uint8_t*>(foo_code.address());
      std::vector<MemoryRange>* pages = i_isolate()->GetCodePages();

      // Wait until after we have created the first function to take the initial
      // number of pages so that this test isn't brittle to irrelevant
      // implementation details.
      if (n == 0) {
        initial_num_code_pages = pages->size();
      }
      num_code_pages = pages->size();

      // Check that the code object was allocation on any of the pages returned
      // by GetCodePages().
      auto it = std::find_if(
          pages->begin(), pages->end(), [foo_code_ptr](const MemoryRange& r) {
            const uint8_t* page_start =
                reinterpret_cast<const uint8_t*>(r.start);
            const uint8_t* page_end = page_start + r.length_in_bytes;
            return foo_code_ptr >= page_start && foo_code_ptr < page_end;
          });
      EXPECT_NE(it, pages->end());

      // Store the page that was created just for our functions - we expect it
      // to be removed later.
      if (num_code_pages > initial_num_code_pages) {
        created_page = it->start;
        num_foos_created = n + 1;
        break;
      }
    }
    CHECK_NOT_NULL(created_page);
  }

  // Now delete all our foos and force a GC and check that the page is removed
  // from the list.
  {
    HandleScope scope(i_isolate());
    for (int n = 0; n < num_foos_created; n++) {
      char foo_name[10];
      snprintf(foo_name, sizeof(foo_name), "foo%d", n);
      context()
          ->Global()
          ->Set(context(), NewString(foo_name), v8::Undefined(isolate()))
          .Check();
    }
  }

  InvokeMajorGC();

  std::vector<MemoryRange>* pages = i_isolate()->GetCodePages();
  auto it = std::find_if(
      pages->begin(), pages->end(),
      [created_page](const MemoryRange& r) { return r.start == created_page; });
  EXPECT_EQ(it, pages->end());
}

TEST_F(CodePagesTest, LargeCodeObject) {
  // We don't want incremental marking to start which could cause the code to
  // not be collected on the CollectGarbage() call.
  ManualGCScope manual_gc_scope(i_isolate());
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      i_isolate()->heap());

  if (!i_isolate()->RequiresCodeRange() && !kHaveCodePages) return;

  // Create a big function that ends up in CODE_LO_SPACE.
  const int instruction_size = PageMetadata::kPageSize + 1;
  EXPECT_GT(instruction_size, MemoryChunkLayout::MaxRegularCodeObjectSize());
  std::unique_ptr<uint8_t[]> instructions(new uint8_t[instruction_size]);

  CodeDesc desc;
  desc.buffer = instructions.get();
  desc.buffer_size = instruction_size;
  desc.instr_size = instruction_size;
  desc.reloc_size = 0;
  desc.constant_pool_size = 0;
  desc.unwinding_info = nullptr;
  desc.unwinding_info_size = 0;
  desc.origin = nullptr;

  Address stale_code_address;

  {
    HandleScope scope(i_isolate());
    IndirectHandle<Code> foo_code =
        Factory::CodeBuilder(i_isolate(), desc, CodeKind::FOR_TESTING).Build();
    IndirectHandle<InstructionStream> foo_istream(
        foo_code->instruction_stream(), i_isolate());

    EXPECT_TRUE(i_isolate()->heap()->InSpace(*foo_istream, CODE_LO_SPACE));

    std::vector<MemoryRange>* pages = i_isolate()->GetCodePages();

    if (i_isolate()->RequiresCodeRange()) {
      EXPECT_TRUE(PagesContainsAddress(pages, foo_istream->address()));
    } else {
      EXPECT_TRUE(PagesHasExactPage(pages, foo_istream->address()));
    }

    stale_code_address = foo_istream->address();
  }

  // Delete the large code object.
  InvokeMajorGC();
  EXPECT_TRUE(
      !i_isolate()->heap()->InSpaceSlow(stale_code_address, CODE_LO_SPACE));

  // Check that it was removed from CodePages.
  std::vector<MemoryRange>* pages = i_isolate()->GetCodePages();
  EXPECT_TRUE(!PagesHasExactPage(pages, stale_code_address));
}

static constexpr size_t kBufSize = v8::Isolate::kMinCodePagesBufferSize;

class SignalSender : public sampler::Sampler {
 public:
  explicit SignalSender(v8::Isolate* isolate) : sampler::Sampler(isolate) {}

  // Called during the signal/thread suspension.
  void SampleStack(const v8::RegisterState& regs) override {
    MemoryRange* code_pages_copy = code_pages_copy_.load();
    CHECK_NOT_NULL(code_pages_copy);
    size_t num_pages = isolate_->CopyCodePages(kBufSize, code_pages_copy);
    EXPECT_LE(num_pages, kBufSize);
    sample_semaphore_.Signal();
  }

  // Called on the sampling thread to trigger a sample. Blocks until the sample
  // is finished.
  void SampleIntoVector(MemoryRange output_buffer[]) {
    code_pages_copy_.store(output_buffer);
    DoSample();
    sample_semaphore_.Wait();
    code_pages_copy_.store(nullptr);
  }

 private:
  base::Semaphore sample_semaphore_{0};
  std::atomic<MemoryRange*> code_pages_copy_{nullptr};
};

class SamplingThread : public base::Thread {
 public:
  explicit SamplingThread(SignalSender* signal_sender)
      : base::Thread(base::Thread::Options("SamplingThread")),
        signal_sender_(signal_sender) {}

  // Blocks until a sample is taken.
  void TriggerSample() { signal_sender_->SampleIntoVector(code_pages_copy_); }

  void Run() override {
    while (running_.load()) {
      TriggerSample();
    }
  }

  // Called from the main thread. Blocks until a sample is taken. Not
  // thread-safe so do not call while this thread is running.
  static std::vector<MemoryRange> DoSynchronousSample(v8::Isolate* isolate) {
    MemoryRange code_pages_copy[kBufSize];
    size_t num_pages = isolate->CopyCodePages(kBufSize, code_pages_copy);
    EXPECT_LE(num_pages, kBufSize);
    return std::vector<MemoryRange>{code_pages_copy,
                                    &code_pages_copy[num_pages]};
  }

  void Stop() { running_.store(false); }

 private:
  std::atomic_bool running_{true};
  SignalSender* signal_sender_;
  MemoryRange code_pages_copy_[kBufSize];
};

TEST_F(CodePagesTest, LargeCodeObjectWithSignalHandler) {
  // We don't want incremental marking to start which could cause the code to
  // not be collected on the CollectGarbage() call.
  ManualGCScope manual_gc_scope(i_isolate());
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      i_isolate()->heap());

  if (!i_isolate()->RequiresCodeRange() && !kHaveCodePages) return;

  // Create a big function that ends up in CODE_LO_SPACE.
  const int instruction_size = PageMetadata::kPageSize + 1;
  EXPECT_GT(instruction_size, MemoryChunkLayout::MaxRegularCodeObjectSize());
  std::unique_ptr<uint8_t[]> instructions(new uint8_t[instruction_size]);

  CodeDesc desc;
  desc.buffer = instructions.get();
  desc.buffer_size = instruction_size;
  desc.instr_size = instruction_size;
  desc.reloc_size = 0;
  desc.constant_pool_size = 0;
  desc.unwinding_info = nullptr;
  desc.unwinding_info_size = 0;
  desc.origin = nullptr;

  Address stale_code_address;

  SignalSender signal_sender(isolate());
  signal_sender.Start();
  // Take an initial sample.
  std::vector<MemoryRange> initial_pages =
      SamplingThread::DoSynchronousSample(isolate());
  SamplingThread sampling_thread(&signal_sender);

  sampling_thread.StartSynchronously();

  {
    HandleScope scope(i_isolate());
    IndirectHandle<Code> foo_code =
        Factory::CodeBuilder(i_isolate(), desc, CodeKind::FOR_TESTING).Build();
    IndirectHandle<InstructionStream> foo_istream(
        foo_code->instruction_stream(), i_isolate());

    EXPECT_TRUE(i_isolate()->heap()->InSpace(*foo_istream, CODE_LO_SPACE));

    // Do a synchronous sample to ensure that we capture the state with the
    // extra code page.
    sampling_thread.Stop();
    sampling_thread.Join();

    // Check that the page was added.
    std::vector<MemoryRange> pages =
        SamplingThread::DoSynchronousSample(isolate());
    if (i_isolate()->RequiresCodeRange()) {
      EXPECT_TRUE(PagesContainsAddress(&pages, foo_istream->address()));
    } else {
      EXPECT_TRUE(PagesHasExactPage(&pages, foo_istream->address()));
    }

    stale_code_address = foo_istream->address();
  }

  // Start async sampling again to detect threading issues.
  sampling_thread.StartSynchronously();

  // Delete the large code object.
  InvokeMajorGC();
  EXPECT_TRUE(
      !i_isolate()->heap()->InSpaceSlow(stale_code_address, CODE_LO_SPACE));

  sampling_thread.Stop();
  sampling_thread.Join();

  std::vector<MemoryRange> pages =
      SamplingThread::DoSynchronousSample(isolate());
  EXPECT_TRUE(!PagesHasExactPage(&pages, stale_code_address));

  signal_sender.Stop();
}

TEST_F(CodePagesTest, Sorted) {
  // We don't want incremental marking to start which could cause the code to
  // not be collected on the CollectGarbage() call.
  ManualGCScope manual_gc_scope(i_isolate());
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      i_isolate()->heap());

  if (!i_isolate()->RequiresCodeRange() && !kHaveCodePages) return;

  // Create a big function that ends up in CODE_LO_SPACE.
  const int instruction_size = PageMetadata::kPageSize + 1;
  EXPECT_GT(instruction_size, MemoryChunkLayout::MaxRegularCodeObjectSize());
  std::unique_ptr<uint8_t[]> instructions(new uint8_t[instruction_size]);

  CodeDesc desc;
  desc.buffer = instructions.get();
  desc.buffer_size = instruction_size;
  desc.instr_size = instruction_size;
  desc.reloc_size = 0;
  desc.constant_pool_size = 0;
  desc.unwinding_info = nullptr;
  desc.unwinding_info_size = 0;
  desc.origin = nullptr;

  // Take an initial sample.
  std::vector<MemoryRange> initial_pages =
      SamplingThread::DoSynchronousSample(isolate());
  size_t initial_num_pages = initial_pages.size();

  auto compare = [](const MemoryRange& a, const MemoryRange& b) {
    return a.start < b.start;
  };
  {
    HandleScope outer_scope(i_isolate());
    IndirectHandle<InstructionStream> code1, code3;
    Address code2_address;

    code1 =
        handle(Factory::CodeBuilder(i_isolate(), desc, CodeKind::FOR_TESTING)
                   .Build()
                   ->instruction_stream(),
               i_isolate());
    EXPECT_TRUE(i_isolate()->heap()->InSpace(*code1, CODE_LO_SPACE));

    {
      HandleScope scope(i_isolate());

      // Create three large code objects, we'll delete the middle one and check
      // everything is still sorted.
      DirectHandle<InstructionStream> code2(
          Factory::CodeBuilder(i_isolate(), desc, CodeKind::FOR_TESTING)
              .Build()
              ->instruction_stream(),
          i_isolate());
      EXPECT_TRUE(i_isolate()->heap()->InSpace(*code2, CODE_LO_SPACE));
      code3 =
          handle(Factory::CodeBuilder(i_isolate(), desc, CodeKind::FOR_TESTING)
                     .Build()
                     ->instruction_stream(),
                 i_isolate());
      EXPECT_TRUE(i_isolate()->heap()->InSpace(*code3, CODE_LO_SPACE));

      code2_address = code2->address();
      EXPECT_TRUE(
          i_isolate()->heap()->InSpaceSlow(code1->address(), CODE_LO_SPACE));
      EXPECT_TRUE(
          i_isolate()->heap()->InSpaceSlow(code2->address(), CODE_LO_SPACE));
      EXPECT_TRUE(
          i_isolate()->heap()->InSpaceSlow(code3->address(), CODE_LO_SPACE));

      // Check that the pages were added.
      std::vector<MemoryRange> pages =
          SamplingThread::DoSynchronousSample(isolate());
      if (i_isolate()->RequiresCodeRange()) {
        EXPECT_EQ(pages.size(), initial_num_pages);
      } else {
        EXPECT_EQ(pages.size(), initial_num_pages + 3);
      }

      EXPECT_TRUE(std::is_sorted(pages.begin(), pages.end(), compare));

      code3 = scope.CloseAndEscape(code3);
    }
    EXPECT_TRUE(
        i_isolate()->heap()->InSpaceSlow(code1->address(), CODE_LO_SPACE));
    EXPECT_TRUE(i_isolate()->heap()->InSpaceSlow(code2_address, CODE_LO_SPACE));
    EXPECT_TRUE(
        i_isolate()->heap()->InSpaceSlow(code3->address(), CODE_LO_SPACE));
    // Delete code2.
    InvokeMajorGC();
    EXPECT_TRUE(
        i_isolate()->heap()->InSpaceSlow(code1->address(), CODE_LO_SPACE));
    EXPECT_TRUE(
        !i_isolate()->heap()->InSpaceSlow(code2_address, CODE_LO_SPACE));
    EXPECT_TRUE(
        i_isolate()->heap()->InSpaceSlow(code3->address(), CODE_LO_SPACE));

    std::vector<MemoryRange> pages =
        SamplingThread::DoSynchronousSample(isolate());
    if (i_isolate()->RequiresCodeRange()) {
      EXPECT_EQ(pages.size(), initial_num_pages);
    } else {
      EXPECT_EQ(pages.size(), initial_num_pages + 2);
    }
    EXPECT_TRUE(std::is_sorted(pages.begin(), pages.end(), compare));
  }
}

}  // namespace test_code_pages
}  // namespace internal
}  // namespace v8

"""

```