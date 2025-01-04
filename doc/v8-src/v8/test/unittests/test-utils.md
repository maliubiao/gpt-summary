Response: The user wants to understand the functionality of the C++ source code file `v8/test/unittests/test-utils.cc`.

I need to analyze the code and identify its main purpose and the functionalities it provides.

Based on the code, the file seems to provide utility classes for writing unit tests for the V8 JavaScript engine.

Specifically, it appears to handle:
- Creating and managing V8 isolates for testing.
- Optionally enabling and tracking internal counters within an isolate.
- Saving and restoring V8 flags to avoid interference between tests.
这个C++源代码文件 `v8/test/unittests/test-utils.cc` 的主要功能是 **为 V8 JavaScript 引擎的单元测试提供一些基础的工具和辅助类**。

具体来说，它实现了以下几个关键功能：

1. **`IsolateWrapper` 类**:
   - **创建和管理 V8 Isolate (隔离区)**：这是 V8 运行时环境的基本单元。`IsolateWrapper` 负责创建新的 `v8::Isolate` 实例，并管理其生命周期，包括初始化、进入/退出上下文、以及在析构时正确地释放资源。
   - **可选的计数器支持**: 允许在测试中启用内部计数器。如果启用了计数器模式 (`kEnableCounters`)，`IsolateWrapper` 会维护一个 `CounterMap` 来存储计数器的值，并设置一个回调函数 (`counter_lookup_callback`)，使得 V8 内部可以访问和更新这些计数器。这对于测试 V8 内部行为和性能指标非常有用。
   - **提供默认的 ArrayBuffer 分配器**:  在创建 Isolate 时，会关联一个默认的 `ArrayBuffer` 分配器。

2. **`SaveFlags` 类 (在 `internal` 命名空间中)**:
   - **保存和恢复 V8 标志 (Flags)**：V8 引擎有许多可以通过命令行标志进行配置的选项。`SaveFlags` 类的作用是在构造时保存所有 V8 标志的当前值，并在析构时将这些标志恢复到原来的值。
   - **保证测试独立性**: 这对于确保单元测试的独立性和可重复性至关重要。通过保存和恢复标志，可以避免一个测试中修改的标志影响到其他测试。

总而言之， `v8/test/unittests/test-utils.cc` 提供了一些便利的工具类，使得编写 V8 单元测试更加容易和可靠。它主要关注于隔离测试环境、管理 V8 运行时实例以及处理 V8 的配置选项。
Prompt: ```这是目录为v8/test/unittests/test-utils.cc的一个c++源代码文件， 请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/unittests/test-utils.h"

#include "include/libplatform/libplatform.h"
#include "include/v8-isolate.h"
#include "src/api/api-inl.h"
#include "src/base/platform/time.h"
#include "src/execution/isolate.h"
#include "src/flags/flags.h"
#include "src/heap/cppgc-js/cpp-heap.h"
#include "src/init/v8.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/heap/heap-utils.h"

namespace v8 {

namespace {
// counter_lookup_callback doesn't pass through any state information about
// the current Isolate, so we have to store the current counter map somewhere.
// Fortunately tests run serially, so we can just store it in a static global.
CounterMap* kCurrentCounterMap = nullptr;
}  // namespace

IsolateWrapper::IsolateWrapper(CountersMode counters_mode)
    : array_buffer_allocator_(
          v8::ArrayBuffer::Allocator::NewDefaultAllocator()) {
  CHECK_NULL(kCurrentCounterMap);

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = array_buffer_allocator_.get();

  if (counters_mode == kEnableCounters) {
    counter_map_ = std::make_unique<CounterMap>();
    kCurrentCounterMap = counter_map_.get();

    create_params.counter_lookup_callback = [](const char* name) {
      CHECK_NOT_NULL(kCurrentCounterMap);
      // If the name doesn't exist in the counter map, operator[] will default
      // initialize it to zero.
      return &(*kCurrentCounterMap)[name];
    };
  } else {
    create_params.counter_lookup_callback = [](const char* name) -> int* {
      return nullptr;
    };
  }

  isolate_ = v8::Isolate::New(create_params);
  CHECK_NOT_NULL(isolate());
}

IsolateWrapper::~IsolateWrapper() {
  v8::Platform* platform = internal::V8::GetCurrentPlatform();
  CHECK_NOT_NULL(platform);
  isolate_->Enter();
  while (platform::PumpMessageLoop(platform, isolate())) continue;
  isolate_->Exit();
  isolate_->Dispose();
  if (counter_map_) {
    CHECK_EQ(kCurrentCounterMap, counter_map_.get());
    kCurrentCounterMap = nullptr;
  } else {
    CHECK_NULL(kCurrentCounterMap);
  }
}

namespace internal {

SaveFlags::SaveFlags() {
  // For each flag, save the current flag value.
#define FLAG_MODE_APPLY(ftype, ctype, nam, def, cmt) \
  SAVED_##nam = v8_flags.nam.value();
#include "src/flags/flag-definitions.h"
#undef FLAG_MODE_APPLY
}

SaveFlags::~SaveFlags() {
  // For each flag, set back the old flag value if it changed (don't write the
  // flag if it didn't change, to keep TSAN happy).
#define FLAG_MODE_APPLY(ftype, ctype, nam, def, cmt) \
  if (SAVED_##nam != v8_flags.nam.value()) {         \
    v8_flags.nam = SAVED_##nam;                      \
  }
#include "src/flags/flag-definitions.h"  // NOLINT
#undef FLAG_MODE_APPLY
}

}  // namespace internal
}  // namespace v8

"""
```