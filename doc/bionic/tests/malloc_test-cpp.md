Response:
The user wants a summary of the functionality of the C++ source code file `bionic/tests/malloc_test.cpp`. This file is part of Android's Bionic library and contains tests related to memory allocation functions.

Therefore, the summary should focus on the purpose of the file, which is to test the implementation of `malloc` and related functions in Bionic.
这是对 Android Bionic 库中 `bionic/tests/malloc_test.cpp` 文件的功能归纳。

总的来说，这个文件的主要功能是**测试 Android Bionic 库中内存分配相关函数（如 `malloc`, `calloc`, `realloc`, `free`, `memalign`, `pvalloc`, `valloc` 等）的正确性和健壮性**。

具体来说，它通过编写一系列的单元测试用例，来验证这些内存分配函数在各种场景下的行为是否符合预期，包括：

* **基本功能测试:**  验证 `malloc`, `calloc` 能否成功分配内存，`free` 能否正确释放内存。
* **边界条件测试:** 测试在分配大小为 0，或非常大的内存时，函数的行为。
* **溢出测试:**  检查当请求分配过大内存导致溢出时，函数是否能正确返回错误。
* **对齐测试:** 验证 `memalign`, `pvalloc`, `valloc` 等函数是否能按照要求返回对齐的内存地址。
* **`realloc` 功能测试:**  测试 `realloc` 在扩大、缩小已分配内存块以及在 `malloc` 和 `calloc` 分配的内存上操作时的正确性。
* **`malloc_info` 和 `mallinfo` 测试:**  验证获取内存分配信息的接口是否能正常工作，返回的数据是否合理。
* **`mallopt` 功能测试:**  测试 `mallopt` 函数设置内存分配器选项的功能。
* **线程安全相关测试 (部分体现):** 虽然这段代码没有明显的并发测试，但存在 `M_THREAD_DISABLE_MEM_INIT` 这样的 mallopt 选项，暗示了对线程安全性的考虑。
* **与 Android 特性相关的测试:**  例如，通过 `#if defined(__BIONIC__)` 可以看到一些特定于 Bionic 的测试。
* **对齐的详细测试:** 针对不同数据类型以及 Android 平台特定的对齐要求进行了验证。
* **`reallocarray` 测试:** 验证 `reallocarray` 函数的功能，它用于分配指定数量和大小的内存块。

简而言之，`malloc_test.cpp` 是一个全面的内存分配功能测试套件，用于确保 Android Bionic 库提供的内存管理功能稳定可靠。

### 提示词
```
这是目录为bionic/tests/malloc_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <elf.h>
#include <limits.h>
#include <malloc.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/cdefs.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <tinyxml2.h>

#include <android-base/file.h>
#include <android-base/test_utils.h>

#include "DoNotOptimize.h"
#include "utils.h"

#if defined(__BIONIC__)

#include "SignalUtils.h"
#include "dlext_private_tests.h"

#include "platform/bionic/malloc.h"
#include "platform/bionic/mte.h"
#include "platform/bionic/reserved_signals.h"
#include "private/bionic_config.h"

#define HAVE_REALLOCARRAY 1

#elif defined(__GLIBC__)

#define HAVE_REALLOCARRAY __GLIBC_PREREQ(2, 26)

#elif defined(ANDROID_HOST_MUSL)

#define HAVE_REALLOCARRAY 1

#endif

TEST(malloc, malloc_std) {
  // Simple malloc test.
  void *ptr = malloc(100);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(100U, malloc_usable_size(ptr));
  free(ptr);
}

TEST(malloc, malloc_overflow) {
  SKIP_WITH_HWASAN;
  errno = 0;
  ASSERT_EQ(nullptr, malloc(SIZE_MAX));
  ASSERT_ERRNO(ENOMEM);
}

TEST(malloc, calloc_std) {
  // Simple calloc test.
  size_t alloc_len = 100;
  char *ptr = (char *)calloc(1, alloc_len);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(alloc_len, malloc_usable_size(ptr));
  for (size_t i = 0; i < alloc_len; i++) {
    ASSERT_EQ(0, ptr[i]);
  }
  free(ptr);
}

TEST(malloc, calloc_mem_init_disabled) {
#if defined(__BIONIC__)
  // calloc should still zero memory if mem-init is disabled.
  // With jemalloc the mallopts will fail but that shouldn't affect the
  // execution of the test.
  mallopt(M_THREAD_DISABLE_MEM_INIT, 1);
  size_t alloc_len = 100;
  char *ptr = reinterpret_cast<char*>(calloc(1, alloc_len));
  for (size_t i = 0; i < alloc_len; i++) {
    ASSERT_EQ(0, ptr[i]);
  }
  free(ptr);
  mallopt(M_THREAD_DISABLE_MEM_INIT, 0);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(malloc, calloc_illegal) {
  SKIP_WITH_HWASAN;
  errno = 0;
  ASSERT_EQ(nullptr, calloc(-1, 100));
  ASSERT_ERRNO(ENOMEM);
}

TEST(malloc, calloc_overflow) {
  SKIP_WITH_HWASAN;
  errno = 0;
  ASSERT_EQ(nullptr, calloc(1, SIZE_MAX));
  ASSERT_ERRNO(ENOMEM);
  errno = 0;
  ASSERT_EQ(nullptr, calloc(SIZE_MAX, SIZE_MAX));
  ASSERT_ERRNO(ENOMEM);
  errno = 0;
  ASSERT_EQ(nullptr, calloc(2, SIZE_MAX));
  ASSERT_ERRNO(ENOMEM);
  errno = 0;
  ASSERT_EQ(nullptr, calloc(SIZE_MAX, 2));
  ASSERT_ERRNO(ENOMEM);
}

TEST(malloc, memalign_multiple) {
  SKIP_WITH_HWASAN << "hwasan requires power of 2 alignment";
  // Memalign test where the alignment is any value.
  for (size_t i = 0; i <= 12; i++) {
    for (size_t alignment = 1 << i; alignment < (1U << (i+1)); alignment++) {
      char *ptr = reinterpret_cast<char*>(memalign(alignment, 100));
      ASSERT_TRUE(ptr != nullptr) << "Failed at alignment " << alignment;
      ASSERT_LE(100U, malloc_usable_size(ptr)) << "Failed at alignment " << alignment;
      ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(ptr) % ((1U << i)))
          << "Failed at alignment " << alignment;
      free(ptr);
    }
  }
}

TEST(malloc, memalign_overflow) {
  SKIP_WITH_HWASAN;
  ASSERT_EQ(nullptr, memalign(4096, SIZE_MAX));
}

TEST(malloc, memalign_non_power2) {
  SKIP_WITH_HWASAN;
  void* ptr;
  for (size_t align = 0; align <= 256; align++) {
    ptr = memalign(align, 1024);
    ASSERT_TRUE(ptr != nullptr) << "Failed at align " << align;
    free(ptr);
  }
}

TEST(malloc, memalign_realloc) {
  // Memalign and then realloc the pointer a couple of times.
  for (size_t alignment = 1; alignment <= 4096; alignment <<= 1) {
    char *ptr = (char*)memalign(alignment, 100);
    ASSERT_TRUE(ptr != nullptr);
    ASSERT_LE(100U, malloc_usable_size(ptr));
    ASSERT_EQ(0U, (intptr_t)ptr % alignment);
    memset(ptr, 0x23, 100);

    ptr = (char*)realloc(ptr, 200);
    ASSERT_TRUE(ptr != nullptr);
    ASSERT_LE(200U, malloc_usable_size(ptr));
    ASSERT_TRUE(ptr != nullptr);
    for (size_t i = 0; i < 100; i++) {
      ASSERT_EQ(0x23, ptr[i]);
    }
    memset(ptr, 0x45, 200);

    ptr = (char*)realloc(ptr, 300);
    ASSERT_TRUE(ptr != nullptr);
    ASSERT_LE(300U, malloc_usable_size(ptr));
    for (size_t i = 0; i < 200; i++) {
      ASSERT_EQ(0x45, ptr[i]);
    }
    memset(ptr, 0x67, 300);

    ptr = (char*)realloc(ptr, 250);
    ASSERT_TRUE(ptr != nullptr);
    ASSERT_LE(250U, malloc_usable_size(ptr));
    for (size_t i = 0; i < 250; i++) {
      ASSERT_EQ(0x67, ptr[i]);
    }
    free(ptr);
  }
}

TEST(malloc, malloc_realloc_larger) {
  // Realloc to a larger size, malloc is used for the original allocation.
  char *ptr = (char *)malloc(100);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(100U, malloc_usable_size(ptr));
  memset(ptr, 67, 100);

  ptr = (char *)realloc(ptr, 200);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(200U, malloc_usable_size(ptr));
  for (size_t i = 0; i < 100; i++) {
    ASSERT_EQ(67, ptr[i]);
  }
  free(ptr);
}

TEST(malloc, malloc_realloc_smaller) {
  // Realloc to a smaller size, malloc is used for the original allocation.
  char *ptr = (char *)malloc(200);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(200U, malloc_usable_size(ptr));
  memset(ptr, 67, 200);

  ptr = (char *)realloc(ptr, 100);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(100U, malloc_usable_size(ptr));
  for (size_t i = 0; i < 100; i++) {
    ASSERT_EQ(67, ptr[i]);
  }
  free(ptr);
}

TEST(malloc, malloc_multiple_realloc) {
  // Multiple reallocs, malloc is used for the original allocation.
  char *ptr = (char *)malloc(200);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(200U, malloc_usable_size(ptr));
  memset(ptr, 0x23, 200);

  ptr = (char *)realloc(ptr, 100);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(100U, malloc_usable_size(ptr));
  for (size_t i = 0; i < 100; i++) {
    ASSERT_EQ(0x23, ptr[i]);
  }

  ptr = (char*)realloc(ptr, 50);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(50U, malloc_usable_size(ptr));
  for (size_t i = 0; i < 50; i++) {
    ASSERT_EQ(0x23, ptr[i]);
  }

  ptr = (char*)realloc(ptr, 150);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(150U, malloc_usable_size(ptr));
  for (size_t i = 0; i < 50; i++) {
    ASSERT_EQ(0x23, ptr[i]);
  }
  memset(ptr, 0x23, 150);

  ptr = (char*)realloc(ptr, 425);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(425U, malloc_usable_size(ptr));
  for (size_t i = 0; i < 150; i++) {
    ASSERT_EQ(0x23, ptr[i]);
  }
  free(ptr);
}

TEST(malloc, calloc_realloc_larger) {
  // Realloc to a larger size, calloc is used for the original allocation.
  char *ptr = (char *)calloc(1, 100);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(100U, malloc_usable_size(ptr));

  ptr = (char *)realloc(ptr, 200);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(200U, malloc_usable_size(ptr));
  for (size_t i = 0; i < 100; i++) {
    ASSERT_EQ(0, ptr[i]);
  }
  free(ptr);
}

TEST(malloc, calloc_realloc_smaller) {
  // Realloc to a smaller size, calloc is used for the original allocation.
  char *ptr = (char *)calloc(1, 200);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(200U, malloc_usable_size(ptr));

  ptr = (char *)realloc(ptr, 100);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(100U, malloc_usable_size(ptr));
  for (size_t i = 0; i < 100; i++) {
    ASSERT_EQ(0, ptr[i]);
  }
  free(ptr);
}

TEST(malloc, calloc_multiple_realloc) {
  // Multiple reallocs, calloc is used for the original allocation.
  char *ptr = (char *)calloc(1, 200);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(200U, malloc_usable_size(ptr));

  ptr = (char *)realloc(ptr, 100);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(100U, malloc_usable_size(ptr));
  for (size_t i = 0; i < 100; i++) {
    ASSERT_EQ(0, ptr[i]);
  }

  ptr = (char*)realloc(ptr, 50);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(50U, malloc_usable_size(ptr));
  for (size_t i = 0; i < 50; i++) {
    ASSERT_EQ(0, ptr[i]);
  }

  ptr = (char*)realloc(ptr, 150);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(150U, malloc_usable_size(ptr));
  for (size_t i = 0; i < 50; i++) {
    ASSERT_EQ(0, ptr[i]);
  }
  memset(ptr, 0, 150);

  ptr = (char*)realloc(ptr, 425);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_LE(425U, malloc_usable_size(ptr));
  for (size_t i = 0; i < 150; i++) {
    ASSERT_EQ(0, ptr[i]);
  }
  free(ptr);
}

TEST(malloc, realloc_overflow) {
  SKIP_WITH_HWASAN;
  errno = 0;
  ASSERT_EQ(nullptr, realloc(nullptr, SIZE_MAX));
  ASSERT_ERRNO(ENOMEM);
  void* ptr = malloc(100);
  ASSERT_TRUE(ptr != nullptr);
  errno = 0;
  ASSERT_EQ(nullptr, realloc(ptr, SIZE_MAX));
  ASSERT_ERRNO(ENOMEM);
  free(ptr);
}

#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
extern "C" void* pvalloc(size_t);
extern "C" void* valloc(size_t);
#endif

TEST(malloc, pvalloc_std) {
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
  size_t pagesize = sysconf(_SC_PAGESIZE);
  void* ptr = pvalloc(100);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_TRUE((reinterpret_cast<uintptr_t>(ptr) & (pagesize-1)) == 0);
  ASSERT_LE(pagesize, malloc_usable_size(ptr));
  free(ptr);
#else
  GTEST_SKIP() << "pvalloc not supported.";
#endif
}

TEST(malloc, pvalloc_overflow) {
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
  ASSERT_EQ(nullptr, pvalloc(SIZE_MAX));
#else
  GTEST_SKIP() << "pvalloc not supported.";
#endif
}

TEST(malloc, valloc_std) {
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
  size_t pagesize = sysconf(_SC_PAGESIZE);
  void* ptr = valloc(100);
  ASSERT_TRUE(ptr != nullptr);
  ASSERT_TRUE((reinterpret_cast<uintptr_t>(ptr) & (pagesize-1)) == 0);
  free(ptr);
#else
  GTEST_SKIP() << "valloc not supported.";
#endif
}

TEST(malloc, valloc_overflow) {
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
  ASSERT_EQ(nullptr, valloc(SIZE_MAX));
#else
  GTEST_SKIP() << "valloc not supported.";
#endif
}

TEST(malloc, malloc_info) {
#ifdef __BIONIC__
  SKIP_WITH_HWASAN; // hwasan does not implement malloc_info

  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);
  FILE* fp = fdopen(tf.fd, "w+");
  tf.release();
  ASSERT_TRUE(fp != nullptr);
  ASSERT_EQ(0, malloc_info(0, fp));
  ASSERT_EQ(0, fclose(fp));

  std::string contents;
  ASSERT_TRUE(android::base::ReadFileToString(tf.path, &contents));

  tinyxml2::XMLDocument doc;
  ASSERT_EQ(tinyxml2::XML_SUCCESS, doc.Parse(contents.c_str()));

  auto root = doc.FirstChildElement();
  ASSERT_NE(nullptr, root);
  ASSERT_STREQ("malloc", root->Name());
  std::string version(root->Attribute("version"));
  if (version == "jemalloc-1") {
    auto arena = root->FirstChildElement();
    for (; arena != nullptr; arena = arena->NextSiblingElement()) {
      int val;

      ASSERT_STREQ("heap", arena->Name());
      ASSERT_EQ(tinyxml2::XML_SUCCESS, arena->QueryIntAttribute("nr", &val));
      ASSERT_EQ(tinyxml2::XML_SUCCESS,
                arena->FirstChildElement("allocated-large")->QueryIntText(&val));
      ASSERT_EQ(tinyxml2::XML_SUCCESS,
                arena->FirstChildElement("allocated-huge")->QueryIntText(&val));
      ASSERT_EQ(tinyxml2::XML_SUCCESS,
                arena->FirstChildElement("allocated-bins")->QueryIntText(&val));
      ASSERT_EQ(tinyxml2::XML_SUCCESS,
                arena->FirstChildElement("bins-total")->QueryIntText(&val));

      auto bin = arena->FirstChildElement("bin");
      for (; bin != nullptr; bin = bin ->NextSiblingElement()) {
        if (strcmp(bin->Name(), "bin") == 0) {
          ASSERT_EQ(tinyxml2::XML_SUCCESS, bin->QueryIntAttribute("nr", &val));
          ASSERT_EQ(tinyxml2::XML_SUCCESS,
                    bin->FirstChildElement("allocated")->QueryIntText(&val));
          ASSERT_EQ(tinyxml2::XML_SUCCESS,
                    bin->FirstChildElement("nmalloc")->QueryIntText(&val));
          ASSERT_EQ(tinyxml2::XML_SUCCESS,
                    bin->FirstChildElement("ndalloc")->QueryIntText(&val));
        }
      }
    }
  } else if (version == "scudo-1") {
    auto element = root->FirstChildElement();
    for (; element != nullptr; element = element->NextSiblingElement()) {
      int val;

      ASSERT_STREQ("alloc", element->Name());
      ASSERT_EQ(tinyxml2::XML_SUCCESS, element->QueryIntAttribute("size", &val));
      ASSERT_EQ(tinyxml2::XML_SUCCESS, element->QueryIntAttribute("count", &val));
    }
  } else {
    // Do not verify output for debug malloc.
    ASSERT_TRUE(version == "debug-malloc-1") << "Unknown version: " << version;
  }
  printf("Allocator version: %s\n", version.c_str());
#endif
}

TEST(malloc, malloc_info_matches_mallinfo) {
#ifdef __BIONIC__
  SKIP_WITH_HWASAN; // hwasan does not implement malloc_info

  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);
  FILE* fp = fdopen(tf.fd, "w+");
  tf.release();
  ASSERT_TRUE(fp != nullptr);
  size_t mallinfo_before_allocated_bytes = mallinfo().uordblks;
  ASSERT_EQ(0, malloc_info(0, fp));
  size_t mallinfo_after_allocated_bytes = mallinfo().uordblks;
  ASSERT_EQ(0, fclose(fp));

  std::string contents;
  ASSERT_TRUE(android::base::ReadFileToString(tf.path, &contents));

  tinyxml2::XMLDocument doc;
  ASSERT_EQ(tinyxml2::XML_SUCCESS, doc.Parse(contents.c_str()));

  size_t total_allocated_bytes = 0;
  auto root = doc.FirstChildElement();
  ASSERT_NE(nullptr, root);
  ASSERT_STREQ("malloc", root->Name());
  std::string version(root->Attribute("version"));
  if (version == "jemalloc-1") {
    auto arena = root->FirstChildElement();
    for (; arena != nullptr; arena = arena->NextSiblingElement()) {
      int val;

      ASSERT_STREQ("heap", arena->Name());
      ASSERT_EQ(tinyxml2::XML_SUCCESS, arena->QueryIntAttribute("nr", &val));
      ASSERT_EQ(tinyxml2::XML_SUCCESS,
                arena->FirstChildElement("allocated-large")->QueryIntText(&val));
      total_allocated_bytes += val;
      ASSERT_EQ(tinyxml2::XML_SUCCESS,
                arena->FirstChildElement("allocated-huge")->QueryIntText(&val));
      total_allocated_bytes += val;
      ASSERT_EQ(tinyxml2::XML_SUCCESS,
                arena->FirstChildElement("allocated-bins")->QueryIntText(&val));
      total_allocated_bytes += val;
      ASSERT_EQ(tinyxml2::XML_SUCCESS,
                arena->FirstChildElement("bins-total")->QueryIntText(&val));
    }
    // The total needs to be between the mallinfo call before and after
    // since malloc_info allocates some memory.
    EXPECT_LE(mallinfo_before_allocated_bytes, total_allocated_bytes);
    EXPECT_GE(mallinfo_after_allocated_bytes, total_allocated_bytes);
  } else if (version == "scudo-1") {
    auto element = root->FirstChildElement();
    for (; element != nullptr; element = element->NextSiblingElement()) {
      ASSERT_STREQ("alloc", element->Name());
      int size;
      ASSERT_EQ(tinyxml2::XML_SUCCESS, element->QueryIntAttribute("size", &size));
      int count;
      ASSERT_EQ(tinyxml2::XML_SUCCESS, element->QueryIntAttribute("count", &count));
      total_allocated_bytes += size * count;
    }
    // Scudo only gives the information on the primary, so simply make
    // sure that the value is non-zero.
    EXPECT_NE(0U, total_allocated_bytes);
  } else {
    // Do not verify output for debug malloc.
    ASSERT_TRUE(version == "debug-malloc-1") << "Unknown version: " << version;
  }
#endif
}

TEST(malloc, calloc_usable_size) {
  for (size_t size = 1; size <= 2048; size++) {
    void* pointer = malloc(size);
    ASSERT_TRUE(pointer != nullptr);
    memset(pointer, 0xeb, malloc_usable_size(pointer));
    free(pointer);

    // We should get a previous pointer that has been set to non-zero.
    // If calloc does not zero out all of the data, this will fail.
    uint8_t* zero_mem = reinterpret_cast<uint8_t*>(calloc(1, size));
    ASSERT_TRUE(pointer != nullptr);
    size_t usable_size = malloc_usable_size(zero_mem);
    for (size_t i = 0; i < usable_size; i++) {
      ASSERT_EQ(0, zero_mem[i]) << "Failed at allocation size " << size << " at byte " << i;
    }
    free(zero_mem);
  }
}

TEST(malloc, malloc_0) {
  void* p = malloc(0);
  ASSERT_TRUE(p != nullptr);
  free(p);
}

TEST(malloc, calloc_0_0) {
  void* p = calloc(0, 0);
  ASSERT_TRUE(p != nullptr);
  free(p);
}

TEST(malloc, calloc_0_1) {
  void* p = calloc(0, 1);
  ASSERT_TRUE(p != nullptr);
  free(p);
}

TEST(malloc, calloc_1_0) {
  void* p = calloc(1, 0);
  ASSERT_TRUE(p != nullptr);
  free(p);
}

TEST(malloc, realloc_nullptr_0) {
  // realloc(nullptr, size) is actually malloc(size).
  void* p = realloc(nullptr, 0);
  ASSERT_TRUE(p != nullptr);
  free(p);
}

TEST(malloc, realloc_0) {
  void* p = malloc(1024);
  ASSERT_TRUE(p != nullptr);
  // realloc(p, 0) is actually free(p).
  void* p2 = realloc(p, 0);
  ASSERT_TRUE(p2 == nullptr);
}

constexpr size_t MAX_LOOPS = 200;

// Make sure that memory returned by malloc is aligned to allow these data types.
TEST(malloc, verify_alignment) {
  uint32_t** values_32 = new uint32_t*[MAX_LOOPS];
  uint64_t** values_64 = new uint64_t*[MAX_LOOPS];
  long double** values_ldouble = new long double*[MAX_LOOPS];
  // Use filler to attempt to force the allocator to get potentially bad alignments.
  void** filler = new void*[MAX_LOOPS];

  for (size_t i = 0; i < MAX_LOOPS; i++) {
    // Check uint32_t pointers.
    filler[i] = malloc(1);
    ASSERT_TRUE(filler[i] != nullptr);

    values_32[i] = reinterpret_cast<uint32_t*>(malloc(sizeof(uint32_t)));
    ASSERT_TRUE(values_32[i] != nullptr);
    *values_32[i] = i;
    ASSERT_EQ(*values_32[i], i);
    ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(values_32[i]) & (sizeof(uint32_t) - 1));

    free(filler[i]);
  }

  for (size_t i = 0; i < MAX_LOOPS; i++) {
    // Check uint64_t pointers.
    filler[i] = malloc(1);
    ASSERT_TRUE(filler[i] != nullptr);

    values_64[i] = reinterpret_cast<uint64_t*>(malloc(sizeof(uint64_t)));
    ASSERT_TRUE(values_64[i] != nullptr);
    *values_64[i] = 0x1000 + i;
    ASSERT_EQ(*values_64[i], 0x1000 + i);
    ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(values_64[i]) & (sizeof(uint64_t) - 1));

    free(filler[i]);
  }

  for (size_t i = 0; i < MAX_LOOPS; i++) {
    // Check long double pointers.
    filler[i] = malloc(1);
    ASSERT_TRUE(filler[i] != nullptr);

    values_ldouble[i] = reinterpret_cast<long double*>(malloc(sizeof(long double)));
    ASSERT_TRUE(values_ldouble[i] != nullptr);
    *values_ldouble[i] = 5.5 + i;
    ASSERT_DOUBLE_EQ(*values_ldouble[i], 5.5 + i);
    // 32 bit glibc has a long double size of 12 bytes, so hardcode the
    // required alignment to 0x7.
#if !defined(__BIONIC__) && !defined(__LP64__)
    ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(values_ldouble[i]) & 0x7);
#else
    ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(values_ldouble[i]) & (sizeof(long double) - 1));
#endif

    free(filler[i]);
  }

  for (size_t i = 0; i < MAX_LOOPS; i++) {
    free(values_32[i]);
    free(values_64[i]);
    free(values_ldouble[i]);
  }

  delete[] filler;
  delete[] values_32;
  delete[] values_64;
  delete[] values_ldouble;
}

TEST(malloc, mallopt_smoke) {
#if defined(__BIONIC__)
  errno = 0;
  ASSERT_EQ(0, mallopt(-1000, 1));
  // mallopt doesn't set errno.
  ASSERT_ERRNO(0);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(malloc, mallopt_decay) {
#if defined(__BIONIC__)
  SKIP_WITH_HWASAN << "hwasan does not implement mallopt";
  ASSERT_EQ(1, mallopt(M_DECAY_TIME, -1));
  ASSERT_EQ(1, mallopt(M_DECAY_TIME, 1));
  ASSERT_EQ(1, mallopt(M_DECAY_TIME, 0));
  ASSERT_EQ(1, mallopt(M_DECAY_TIME, 1));
  ASSERT_EQ(1, mallopt(M_DECAY_TIME, 0));
  ASSERT_EQ(1, mallopt(M_DECAY_TIME, -1));
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(malloc, mallopt_purge) {
#if defined(__BIONIC__)
  SKIP_WITH_HWASAN << "hwasan does not implement mallopt";
  ASSERT_EQ(1, mallopt(M_PURGE, 0));
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(malloc, mallopt_purge_all) {
#if defined(__BIONIC__)
  SKIP_WITH_HWASAN << "hwasan does not implement mallopt";
  ASSERT_EQ(1, mallopt(M_PURGE_ALL, 0));
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(malloc, mallopt_log_stats) {
#if defined(__BIONIC__)
  SKIP_WITH_HWASAN << "hwasan does not implement mallopt";
  ASSERT_EQ(1, mallopt(M_LOG_STATS, 0));
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

// Verify that all of the mallopt values are unique.
TEST(malloc, mallopt_unique_params) {
#if defined(__BIONIC__)
  std::vector<std::pair<int, std::string>> params{
      std::make_pair(M_DECAY_TIME, "M_DECAY_TIME"),
      std::make_pair(M_PURGE, "M_PURGE"),
      std::make_pair(M_PURGE_ALL, "M_PURGE_ALL"),
      std::make_pair(M_MEMTAG_TUNING, "M_MEMTAG_TUNING"),
      std::make_pair(M_THREAD_DISABLE_MEM_INIT, "M_THREAD_DISABLE_MEM_INIT"),
      std::make_pair(M_CACHE_COUNT_MAX, "M_CACHE_COUNT_MAX"),
      std::make_pair(M_CACHE_SIZE_MAX, "M_CACHE_SIZE_MAX"),
      std::make_pair(M_TSDS_COUNT_MAX, "M_TSDS_COUNT_MAX"),
      std::make_pair(M_BIONIC_ZERO_INIT, "M_BIONIC_ZERO_INIT"),
      std::make_pair(M_BIONIC_SET_HEAP_TAGGING_LEVEL, "M_BIONIC_SET_HEAP_TAGGING_LEVEL"),
      std::make_pair(M_LOG_STATS, "M_LOG_STATS"),
  };

  std::unordered_map<int, std::string> all_params;
  for (const auto& param : params) {
    EXPECT_TRUE(all_params.count(param.first) == 0)
        << "mallopt params " << all_params[param.first] << " and " << param.second
        << " have the same value " << param.first;
    all_params.insert(param);
  }
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

#if defined(__BIONIC__)
static void GetAllocatorVersion(bool* allocator_scudo) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);
  FILE* fp = fdopen(tf.fd, "w+");
  tf.release();
  ASSERT_TRUE(fp != nullptr);
  if (malloc_info(0, fp) != 0) {
    *allocator_scudo = false;
    return;
  }
  ASSERT_EQ(0, fclose(fp));

  std::string contents;
  ASSERT_TRUE(android::base::ReadFileToString(tf.path, &contents));

  tinyxml2::XMLDocument doc;
  ASSERT_EQ(tinyxml2::XML_SUCCESS, doc.Parse(contents.c_str()));

  auto root = doc.FirstChildElement();
  ASSERT_NE(nullptr, root);
  ASSERT_STREQ("malloc", root->Name());
  std::string version(root->Attribute("version"));
  *allocator_scudo = (version == "scudo-1");
}
#endif

TEST(malloc, mallopt_scudo_only_options) {
#if defined(__BIONIC__)
  SKIP_WITH_HWASAN << "hwasan does not implement mallopt";
  bool allocator_scudo;
  GetAllocatorVersion(&allocator_scudo);
  if (!allocator_scudo) {
    GTEST_SKIP() << "scudo allocator only test";
  }
  ASSERT_EQ(1, mallopt(M_CACHE_COUNT_MAX, 100));
  ASSERT_EQ(1, mallopt(M_CACHE_SIZE_MAX, 1024 * 1024 * 2));
  ASSERT_EQ(1, mallopt(M_TSDS_COUNT_MAX, 8));
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(malloc, reallocarray_overflow) {
#if HAVE_REALLOCARRAY
  // Values that cause overflow to a result small enough (8 on LP64) that malloc would "succeed".
  size_t a = static_cast<size_t>(INTPTR_MIN + 4);
  size_t b = 2;

  errno = 0;
  ASSERT_TRUE(reallocarray(nullptr, a, b) == nullptr);
  ASSERT_ERRNO(ENOMEM);

  errno = 0;
  ASSERT_TRUE(reallocarray(nullptr, b, a) == nullptr);
  ASSERT_ERRNO(ENOMEM);
#else
  GTEST_SKIP() << "reallocarray not available";
#endif
}

TEST(malloc, reallocarray) {
#if HAVE_REALLOCARRAY
  void* p = reallocarray(nullptr, 2, 32);
  ASSERT_TRUE(p != nullptr);
  ASSERT_GE(malloc_usable_size(p), 64U);
#else
  GTEST_SKIP() << "reallocarray not available";
#endif
}

TEST(malloc, mallinfo) {
#if defined(__BIONIC__) || defined(ANDROID_HOST_MUSL)
  SKIP_WITH_HWASAN << "hwasan does not implement mallinfo";
  static size_t sizes[] = {
    8, 32, 128, 4096, 32768, 131072, 1024000, 10240000, 20480000, 300000000
  };

  static constexpr size_t kMaxAllocs = 50;

  for (size_t size : sizes) {
    // If some of these allocations are stuck in a thread cache, then keep
    // looping until we make an allocation that changes the total size of the
    // memory allocated.
    // jemalloc implementations counts the thread cache allocations against
    // total memory allocated.
    void* ptrs[kMaxAllocs] = {};
    bool pass = false;
    for (size_t i = 0; i < kMaxAllocs; i++) {
      size_t allocated = mallinfo().uordblks;
      ptrs[i] = malloc(size);
      ASSERT_TRUE(ptrs[i] != nullptr);
      size_t new_allocated = mallinfo().uordblks;
      if (allocated != new_allocated) {
        size_t usable_size = malloc_usable_size(ptrs[i]);
        // Only check if the total got bigger by at least allocation size.
        // Sometimes the mallinfo numbers can go backwards due to compaction
        // and/or freeing of cached data.
        if (new_allocated >= allocated + usable_size) {
          pass = true;
          break;
        }
      }
    }
    for (void* ptr : ptrs) {
      free(ptr);
    }
    ASSERT_TRUE(pass)
        << "For size " << size << " allocated bytes did not increase after "
        << kMaxAllocs << " allocations.";
  }
#else
  GTEST_SKIP() << "glibc is broken";
#endif
}

TEST(malloc, mallinfo2) {
#if defined(__BIONIC__) || defined(ANDROID_HOST_MUSL)
  SKIP_WITH_HWASAN << "hwasan does not implement mallinfo2";
  static size_t sizes[] = {8, 32, 128, 4096, 32768, 131072, 1024000, 10240000, 20480000, 300000000};

  static constexpr size_t kMaxAllocs = 50;

  for (size_t size : sizes) {
    // If some of these allocations are stuck in a thread cache, then keep
    // looping until we make an allocation that changes the total size of the
    // memory allocated.
    // jemalloc implementations counts the thread cache allocations against
    // total memory allocated.
    void* ptrs[kMaxAllocs] = {};
    bool pass = false;
    for (size_t i = 0; i < kMaxAllocs; i++) {
      struct mallinfo info = mallinfo();
      struct mallinfo2 info2 = mallinfo2();
      // Verify that mallinfo and mallinfo2 are exactly the same.
      ASSERT_EQ(static_cast<size_t>(info.arena), info2.arena);
      ASSERT_EQ(static_cast<size_t>(info.ordblks), info2.ordblks);
      ASSERT_EQ(static_cast<size_t>(info.smblks), info2.smblks);
      ASSERT_EQ(static_cast<size_t>(info.hblks), info2.hblks);
      ASSERT_EQ(static_cast<size_t>(info.hblkhd), info2.hblkhd);
      ASSERT_EQ(static_cast<size_t>(info.usmblks), info2.usmblks);
      ASSERT_EQ(static_cast<size_t>(info.fsmblks), info2.fsmblks);
      ASSERT_EQ(static_cast<size_t>(info.uordblks), info2.uordblks);
      ASSERT_EQ(static_cast<size_t>(info.fordblks), info2.fordblks);
      ASSERT_EQ(static_cast<size_t>(info.keepcost), info2.keepcost);

      size_t allocated = info2.uordblks;
      ptrs[i] = malloc(size);
      ASSERT_TRUE(ptrs[i] != nullptr);

      info = mallinfo();
      info2 = mallinfo2();
      // Verify that mallinfo and mallinfo2 are exactly the same.
      ASSERT_EQ(static_cast<size_t>(info.arena), info2.arena);
      ASSERT_EQ(static_cast<size_t>(info.ordblks), info2.ordblks);
      ASSERT_EQ(static_cast<size_t>(info.smblks), info2.smblks);
      ASSERT_EQ(static_cast<size_t>(info.hblks), info2.hblks);
      ASSERT_EQ(static_cast<size_t>(info.hblkhd), info2.hblkhd);
      ASSERT_EQ(static_cast<size_t>(info.usmblks), info2.usmblks);
      ASSERT_EQ(static_cast<size_t>(info.fsmblks), info2.fsmblks);
      ASSERT_EQ(static_cast<size_t>(info.uordblks), info2.uordblks);
      ASSERT_EQ(static_cast<size_t>(info.fordblks), info2.fordblks);
      ASSERT_EQ(static_cast<size_t>(info.keepcost), info2.keepcost);

      size_t new_allocated = info2.uordblks;
      if (allocated != new_allocated) {
        size_t usable_size = malloc_usable_size(ptrs[i]);
        // Only check if the total got bigger by at least allocation size.
        // Sometimes the mallinfo2 numbers can go backwards due to compaction
        // and/or freeing of cached data.
        if (new_allocated >= allocated + usable_size) {
          pass = true;
          break;
        }
      }
    }
    for (void* ptr : ptrs) {
      free(ptr);
    }
    ASSERT_TRUE(pass) << "For size " << size << " allocated bytes did not increase after "
                      << kMaxAllocs << " allocations.";
  }
#else
  GTEST_SKIP() << "glibc is broken";
#endif
}

template <typename Type>
void __attribute__((optnone)) VerifyAlignment(Type* floating) {
  size_t expected_alignment = alignof(Type);
  if (expected_alignment != 0) {
    ASSERT_EQ(0U, (expected_alignment - 1) & reinterpret_cast<uintptr_t>(floating))
        << "Expected alignment " << expected_alignment << " ptr value "
        << static_cast<void*>(floating);
  }
}

template <typename Type>
void __attribute__((optnone)) TestAllocateType() {
  // The number of allocations to do in a row. This is to attempt to
  // expose the worst case alignment for native allocators that use
  // bins.
  static constexpr size_t kMaxConsecutiveAllocs = 100;

  // Verify using new directly.
  Type* types[kMaxConsecutiveAllocs];
  for (size_t i = 0; i < kMaxConsecutiveAllocs; i++) {
    types[i] = new Type;
    VerifyAlignment(types[i]);
    if (::testing::Test::HasFatalFailure()) {
      return;
    }
  }
  for (size_t i = 0; i < kMaxConsecutiveAllocs; i++) {
    delete types[i];
  }

  // Verify using malloc.
  for (size_t i = 0; i < kMaxConsecutiveAllocs; i++) {
    types[i] = reinterpret_cast<Type*>(malloc(sizeof(Type)));
    ASSERT_TRUE(types[i] != nullptr);
    VerifyAlignment(types[i]);
    if (::testing::Test::HasFatalFailure()) {
      return;
    }
  }
  for (size_t i = 0; i < kMaxConsecutiveAllocs; i++) {
    free(types[i]);
  }

  // Verify using a vector.
  std::vector<Type> type_vector(kMaxConsecutiveAllocs);
  for (size_t i = 0; i < type_vector.size(); i++) {
    VerifyAlignment(&type_vector[i]);
    if (::testing::Test::HasFatalFailure()) {
      return;
    }
  }
}

#if defined(__ANDROID__)
static void __attribute__((optnone)) AndroidVerifyAlignment(size_t alloc_size, size_t aligned_bytes) {
  void* ptrs[100];
  uintptr_t mask = aligned_bytes - 1;
  for (size_t i = 0; i < sizeof(ptrs) / sizeof(void*); i++) {
    ptrs[i] = malloc(alloc_size);
    ASSERT_TRUE(ptrs[i] != nullptr);
    ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(ptrs[i]) & mask)
        << "Expected at least " << aligned_bytes << " byte alignment: size "
        << alloc_size << " actual ptr " << ptrs[i];
  }
}
#endif

void AlignCheck() {
  // See http://www.open-std.org/jtc1/sc22/wg14/www/docs/summary.htm#dr_445
  // for a discussion of type alignment.
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<float>());
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<double>());
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<long double>());

  ASSERT_NO_FATAL_FAILURE(TestAllocateType<char>());
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<char16_t>());
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<char32_t>());
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<wchar_t>());
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<signed char>());
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<short int>());
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<int>());
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<long int>());
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<long long int>());
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<unsigned char>());
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<unsigned short int>());
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<unsigned int>());
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<unsigned long int>());
  ASSERT_NO_FATAL_FAILURE(TestAllocateType<unsigned long long int>());

#if defined(__ANDROID__)
  // On Android, there is a lot of code that expects certain alignments:
  //  1. Allocations of a size that rounds up to a multiple of 16 bytes
  //     must have at least 16 byte alignment.
  //  2. Allocations of a size that rounds up to a multiple of 8 bytes and
  //     not 16 bytes, are only required to have at least 8 byte alignment.
  // In addition, on Android clang has been configured for 64 bit such that:
  //  3. Allocations <= 8 bytes must be aligned to at least 8 bytes.
  //  4. Allocations > 8 bytes must be aligned to at least 16 bytes.
  // For 32 bit environments, only the first two requirements must be met.

  // See http://www.open-std.org/jtc1/sc22/wg14/www/docs/n2293.htm for
  // a discussion of this alignment mess. The code below is enforcing
  // strong-alignment, since who knows what code depends on this behavior now.
  // As mentioned before, for 64 bit this will enforce the higher
  // req
```