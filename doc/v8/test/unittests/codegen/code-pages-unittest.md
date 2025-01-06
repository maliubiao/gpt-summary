Response: Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Purpose:** The file name `code-pages-unittest.cc` immediately suggests the tests are related to "code pages."  Reading the initial comments confirms this, mentioning "code range" and "code pages" as features being tested. The copyright and license information are standard boilerplate and can be skipped for functional analysis.

2. **Analyze Includes:** The included headers provide clues about the functionalities being tested:
    * `v8-function.h`:  Indicates testing of JavaScript functions.
    * `api-inl.h`:  Suggests interaction with the V8 public API.
    * `code-desc.h`: Likely involves creating or manipulating code descriptions.
    * `globals.h`: Points to global V8 settings or constants.
    * `isolate.h`: Crucial for accessing the V8 isolate, the main execution environment.
    * `handles-inl.h`:  Implies working with V8's handle system for managing objects.
    * `factory.h`: Suggests the creation of V8 objects.
    * `spaces.h`:  Indicates interaction with V8's memory spaces (e.g., code space).
    * `sampler.h`:  Points to testing related to V8's sampling mechanisms.
    * `heap/*.h`:  Confirms testing related to V8's heap management.
    * `test/*.h`: Standard testing utilities.
    * `gtest/gtest.h`:  The testing framework being used.

3. **Examine Namespaces:**  The code uses `namespace v8`, `namespace internal`, and `namespace test_code_pages`. This structure suggests the tests are within V8's internal testing framework and specifically target the "code pages" functionality.

4. **Look for Key Definitions and Constants:**
    * `kHaveCodePages`: This boolean flag, determined by the target architecture (`V8_TARGET_ARCH_ARM`), is critical. It tells us that the behavior being tested differs based on the platform.
    * `foo_source`: This string contains JavaScript code for a function. The `%d` placeholders suggest the tests dynamically generate variations of this function.
    * `getFooCode()`:  This function generates the JavaScript code by replacing the placeholders. This reinforces the idea of testing multiple function instances.

5. **Analyze Helper Functions:** The `namespace { ... }` block contains helper functions:
    * `PagesHasExactPage()` (two overloads):  These functions check if a given memory range exists *exactly* within the list of code pages.
    * `PagesContainsRange()`:  Checks if a given memory range is *contained* within any of the code pages.
    * `PagesContainsAddress()`: A special case of `PagesContainsRange` to check if a specific address is within a code page.

6. **Dissect the Test Cases (using `TEST_F`):** This is where the core functionality is tested. For each test case, identify:
    * **The Goal:** What specific aspect of code pages is being tested?
    * **Conditions:** Are there any platform-specific conditions (`if (!...) return;`)? This is crucial for understanding which tests run where.
    * **Setup:**  What is being set up before the actual test (e.g., creating functions, enabling native syntax)?
    * **Assertions (`EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_NE`, `EXPECT_LE`, `CHECK_NOT_NULL`):** These are the core of the test. What conditions are being verified?
    * **Teardown (Implicit or Explicit):** Is anything explicitly cleaned up (e.g., deleting variables, forcing GC)?

    Here's a breakdown of the purpose of each test:

    * `CodeRangeCorrectContents`:  Verifies the contents of the code pages list when the "code range" feature is enabled. It checks for the presence and size of the main code region and embedded blob code.
    * `CodePagesCorrectContents`: Similar to the above, but for platforms with "code pages" but *without* the "code range."
    * `OptimizedCodeWithCodeRange`:  Tests that optimized code is placed within the allocated code range.
    * `OptimizedCodeWithCodePages`: Tests that optimized code is placed within the allocated code pages on platforms with that feature. It also checks that new code pages are added as needed and can be reclaimed by garbage collection.
    * `LargeCodeObject`: Tests the handling of large code objects that reside in a separate memory space (`CODE_LO_SPACE`) and verifies they are correctly tracked in the code pages.
    * `LargeCodeObjectWithSignalHandler`: This is a more complex test involving a separate thread and signal handling. It checks that code pages are correctly reported even when a signal handler interrupts execution. The use of `sampler::Sampler` and `SamplingThread` is key here.
    * `Sorted`: Tests that the list of code pages remains sorted after allocating and deallocating large code objects.

7. **Identify Key Concepts and Features Being Tested:** Based on the test cases, we can identify the core functionalities being validated:
    * **Code Ranges:**  A contiguous memory region for generated code.
    * **Code Pages:**  Potentially non-contiguous memory pages for generated code.
    * **Embedded Blob Code:**  Pre-compiled code included in the V8 binary.
    * **Optimized Code:**  Code generated by V8's optimizing compilers (Turbofan, Maglev).
    * **Large Code Objects:** Code objects that exceed the size of regular code objects and are placed in a separate space.
    * **Garbage Collection (GC):**  The process of reclaiming unused memory, specifically testing that code pages are released when the code they contain is no longer needed.
    * **Signal Handling:**  Ensuring code page information is accurate even when signals interrupt execution.
    * **Thread Safety:** Implicitly tested by the `LargeCodeObjectWithSignalHandler` test.
    * **Sorting:** Verifying that the code pages are maintained in sorted order.

8. **Synthesize the Summary:**  Combine the information gathered from the previous steps to create a concise summary of the file's functionality. Emphasize the core purpose, the different scenarios tested, and the key concepts involved. The platform-specific nature of the tests (code ranges vs. code pages) should be highlighted.

This step-by-step approach, focusing on the code structure, key definitions, and the purpose of each test case, allows for a thorough understanding of the unittest file's functionality.
这个C++源代码文件 `code-pages-unittest.cc` 是 V8 JavaScript 引擎的单元测试文件，专门用于测试 **代码页 (code pages)** 功能。 代码页是 V8 用来管理其生成的机器码的内存区域。 这个文件涵盖了以下几个主要功能和方面的测试：

**核心功能：代码页的维护和管理**

* **验证代码页列表的内容正确性：**
    * 针对支持代码范围 (Code Range) 的架构 (例如 ARM64, x64)，测试是否正确地报告了代码范围和嵌入式代码 (embedded code) 的内存区域。
    * 针对支持代码页 (Code Pages) 的架构 (例如 ARM32)，测试是否正确地报告了代码页的内存区域，即使没有连续的代码范围。
* **验证优化后的代码被分配到正确的代码页：**
    * 测试使用 Turbofan 或 Maglev 优化器生成的代码是否位于 `Isolate::GetCodePages()` 返回的内存区域中。
    * 测试在代码页功能启用时，随着生成更多优化代码，新的代码页是否会被添加到列表中。
* **验证不再使用的代码页可以被垃圾回收：**
    * 测试当不再有对某个代码页上生成的函数的引用时，该代码页是否会从 `Isolate::GetCodePages()` 返回的列表中移除。
* **验证大型代码对象 (large code object) 的处理：**
    * 测试大于常规代码对象大小限制的代码对象（通常位于 `CODE_LO_SPACE`）是否被正确地包含在代码页列表中。
    * 测试当大型代码对象被垃圾回收后，其对应的代码页信息是否被移除。

**高级功能和并发测试**

* **测试在信号处理程序 (signal handler) 中的代码页访问：**
    * 使用一个单独的线程模拟信号处理程序，测试在信号处理期间获取的代码页列表是否正确，即使此时正在分配或释放代码页。这涉及到并发访问代码页列表的场景。
* **验证代码页列表的排序：**
    * 测试 `Isolate::GetCodePages()` 返回的代码页列表始终是按起始地址排序的，即使在动态分配和释放代码对象后。

**辅助功能测试**

* **辅助函数 `PagesHasExactPage`, `PagesContainsRange`, `PagesContainsAddress`：** 这些辅助函数用于方便地断言代码页列表中是否包含特定的内存页或地址范围。
* **使用 `%%PrepareFunctionForOptimization` 和 `%%OptimizeFunctionOnNextCall`：** 这些内建函数用于触发 JavaScript 函数的优化，以便生成机器码进行测试。

**总体来说，这个单元测试文件的目的是确保 V8 引擎在不同架构下，正确地管理和报告其生成的机器码的内存区域，包括代码范围、代码页以及大型代码对象的处理，并且保证在并发场景下的数据一致性。**  它覆盖了代码页功能的核心逻辑和一些边缘情况，以确保 V8 的代码管理机制的稳定性和可靠性。

通过这些测试，V8 开发者可以验证代码页功能的正确性，确保性能分析工具和其他依赖于代码页信息的工具能够获得准确的数据。

Prompt: ```这是目录为v8/test/unittests/codegen/code-pages-unittest.cc的一个c++源代码文件， 请归纳一下它的功能

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