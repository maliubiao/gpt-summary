Response:
The user wants a summary of the functionality of the C++ code provided, which is a test suite for string manipulation functions in Android's Bionic library. I need to extract the core functionalities being tested and present them concisely.
这是 `bionic/tests/string_test.cpp` 文件代码功能的总结：

这个文件是 Android Bionic 库中字符串处理函数的单元测试。它使用 Google Test 框架来验证 `libc` 中各种字符串操作函数的正确性和健壮性。

主要测试的功能包括：

* **内存操作函数:**
    * `memcpy`:  内存拷贝。
    * `memmove`: 内存移动（可以处理源和目标内存区域重叠的情况）。
    * `memset`:  将内存块设置为指定的值。
    * `memcmp`:  比较两个内存块的内容。
    * `memchr`:  在内存块中查找指定字符首次出现的位置。
    * `mempcpy`: 内存拷贝，并返回目标地址的末尾。
    * `memmem`: 在一个内存块中查找另一个内存块首次出现的位置。
    * `memset_explicit`:  将内存块设置为指定的值，旨在防止编译器优化掉敏感数据的清除操作 (Bionic 特有)。

* **字符串操作函数:**
    * `strlen`:  计算字符串的长度（不包括 null 终止符）。
    * `strcpy`:  字符串拷贝（不进行边界检查，可能导致缓冲区溢出）。
    * `strncpy`:  字符串拷贝，可以指定最大拷贝长度。
    * `strlcpy`:  安全的字符串拷贝，会确保目标字符串以 null 结尾，并返回不包含 null 终止符的拷贝长度 (并非所有系统都支持)。
    * `stpcpy`:  字符串拷贝，并返回目标字符串 null 终止符的地址。
    * `strcat`:  字符串拼接（不进行边界检查，可能导致缓冲区溢出）。
    * `strlcat`:  安全的字符串拼接，会确保目标字符串以 null 结尾，并返回拼接后的字符串长度 (并非所有系统都支持)。
    * `strcmp`:  比较两个字符串。
    * `strncmp`:  比较两个字符串的前 N 个字符。
    * `strchr`:  在一个字符串中查找指定字符首次出现的位置。
    * `strrchr`:  在一个字符串中查找指定字符最后一次出现的位置。
    * `strstr`:  在一个字符串中查找另一个字符串首次出现的位置。
    * `strcasestr`:  忽略大小写在一个字符串中查找另一个字符串首次出现的位置。
    * `strcoll`:  根据当前区域设置比较两个字符串。
    * `strcoll_l`:  根据指定的区域设置比较两个字符串。
    * `strxfrm`:  根据当前区域设置转换字符串。
    * `strxfrm_l`:  根据指定的区域设置转换字符串。
    * `strnlen`:  计算字符串的最大长度，如果在指定的最大长度内未找到 null 终止符则返回最大长度。

* **其他函数:**
    * `basename`:  提取路径名的基本名称（文件名部分）。
    * `strerrorname_np`: 获取错误码对应的名称字符串 (Bionic 特有)。

**与 Android 功能的关系举例:**

这些字符串处理函数是 Android 系统和应用程序开发的基础。Android 框架和 NDK 中大量的操作都依赖于这些函数。

* **例子 1 (memcpy/strcpy):** 当 Android 应用需要传递数据（例如，通过 Binder IPC）或者复制文件内容时，底层的实现可能会使用 `memcpy` 或 `strcpy` 来高效地复制内存区域。
* **例子 2 (strlen):**  Android 系统在处理文本输入、读取配置文件或者解析网络数据包时，经常需要知道字符串的长度，这时就会用到 `strlen`。
* **例子 3 (strcat/strlcat):**  构建动态的文件路径或者 URL 时，可能会使用 `strcat` 或 `strlcat` 将多个字符串拼接在一起。
* **例子 4 (strcmp):**  在权限检查、用户认证或者文件查找等场景中，需要比较字符串是否相等，就会使用 `strcmp`。

**libc 函数的实现细节 (此代码主要关注测试，没有详细实现):**

这个代码文件本身是测试代码，它通过调用 `libc` 提供的字符串函数并断言结果的正确性来验证其功能。要了解 `libc` 函数的具体实现，需要查看 Bionic 的源代码，例如 `bionic/libc/bionic/` 目录下的相关源文件。

**dynamic linker 的功能 (此代码中涉及较少):**

这个代码主要测试字符串函数，与动态链接器的功能关联不大。动态链接器负责在程序启动时加载所需的共享库 (`.so` 文件) 并解析符号引用。

**so 布局样本和链接处理过程:**

与此代码关系不大，但一个典型的 Android `.so` 文件布局可能包含：

* `.text`:  可执行代码段。
* `.rodata`: 只读数据段（例如字符串常量）。
* `.data`:  已初始化的可读写数据段。
* `.bss`:  未初始化的可读写数据段。
* `.dynamic`: 动态链接信息。
* `.symtab`: 符号表。
* `.strtab`: 字符串表。
* `.rel.dyn`, `.rel.plt`: 重定位表。

链接过程大致如下：

1. **编译时链接:** 编译器将源代码编译成目标文件 (`.o`)，其中包含对外部符号的引用。
2. **链接时处理:** 链接器将多个目标文件和共享库合并成一个可执行文件或共享库。它解析符号引用，将代码和数据安排到内存中的合适位置，并生成重定位信息。
3. **运行时链接:** 当程序启动时，动态链接器根据可执行文件中的动态链接信息，加载所需的共享库到内存中。然后，它根据重定位信息，修改代码和数据中的地址，使其指向正确的共享库中的符号。

**假设输入与输出 (在测试用例中体现):**

测试用例中包含了各种假设输入和期望的输出。例如，对于 `strlen` 测试：

* **假设输入:** 一个以 null 结尾的字符串 "hello"。
* **期望输出:**  `strlen` 函数返回 5。

对于 `memcpy` 测试：

* **假设输入:** 源内存区域 "abc"，目标内存区域，长度 3。
* **期望输出:** 目标内存区域的内容变为 "abc"。

**用户或编程常见的使用错误举例:**

* **缓冲区溢出 (strcpy, strcat):** 使用 `strcpy` 或 `strcat` 时，如果源字符串的长度超过目标缓冲区的大小，会导致缓冲区溢出，覆盖相邻的内存区域，可能导致程序崩溃或安全漏洞。
    ```c
    char buffer[5];
    strcpy(buffer, "too long"); // 缓冲区溢出！
    ```
* **未以 null 结尾的字符串 (strlen, strcmp 等):** 许多字符串函数依赖于 null 终止符来判断字符串的结尾。如果传递给这些函数的字符数组没有 null 终止符，可能会导致读取越界。
    ```c
    char buffer[5] = {'a', 'b', 'c', 'd', 'e'};
    strlen(buffer); // 可能读取越界
    ```
* **memmove 源和目标重叠处理不当:**  对于可能发生内存区域重叠的情况，应该使用 `memmove` 而不是 `memcpy`。`memcpy` 在某些重叠情况下可能导致数据错误。

**Android Framework 或 NDK 如何到达这里，Frida Hook 示例:**

1. **Android Framework/NDK 调用:** Android Framework 或 NDK 中的代码（例如 Java 代码通过 JNI 调用 C/C++ 代码）最终可能会调用 Bionic 提供的字符串函数。例如，Java 中的 `String` 类的操作在底层可能依赖于这些 C 函数。
2. **系统调用:**  这些 `libc` 函数通常直接在用户空间执行，不需要特殊的系统调用。
3. **动态链接:**  当应用程序加载时，动态链接器会将应用程序链接到 Bionic 库，使得应用程序可以调用这些字符串函数。

**Frida Hook 示例:**

可以使用 Frida Hook 来拦截对这些字符串函数的调用，查看其参数和返回值。例如，Hook `strlen` 函数：

```javascript
Interceptor.attach(Module.findExportByName("libc.so", "strlen"), {
  onEnter: function(args) {
    console.log("strlen called with argument:", Memory.readUtf8String(args[0]));
  },
  onLeave: function(retval) {
    console.log("strlen returned:", retval.toInt());
  }
});
```

这个 Frida 脚本会在 `strlen` 函数被调用时打印其参数（字符串）和返回值（长度）。可以类似地 Hook 其他字符串函数进行调试。

### 提示词
```
这是目录为bionic/tests/string_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ARGE, DoMemmoveTest);
}

TEST(STRING_TEST, memmove_overread) {
  RunSrcDstBufferOverreadTest(DoMemmoveTest);
}

static void DoMemsetTest(uint8_t* buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    buf[i] = 0;
  }
  int value = (len % 255) + 1;
  ASSERT_EQ(buf, memset(buf, value, len));
  for (size_t i = 0; i < len; i++) {
    ASSERT_EQ(value, buf[i]);
  }
}

TEST(STRING_TEST, memset_align) {
  RunSingleBufferAlignTest(LARGE, DoMemsetTest);
}

static void DoStrlenTest(uint8_t* buf, size_t len) {
  if (len >= 1) {
    memset(buf, (32 + (len % 96)), len - 1);
    buf[len-1] = '\0';
    ASSERT_EQ(len-1, strlen(reinterpret_cast<char*>(buf)));
  }
}

TEST(STRING_TEST, strlen_align) {
  RunSingleBufferAlignTest(LARGE, DoStrlenTest);
}

TEST(STRING_TEST, strlen_overread) {
  RunSingleBufferOverreadTest(DoStrlenTest);
}

static void DoStrcpyTest(uint8_t* src, uint8_t* dst, size_t len) {
  if (len >= 1) {
    memset(src, (32 + (len % 96)), len - 1);
    src[len-1] = '\0';
    memset(dst, 0, len);
    ASSERT_EQ(dst, reinterpret_cast<uint8_t*>(strcpy(reinterpret_cast<char*>(dst),
                                                     reinterpret_cast<char*>(src))));
    ASSERT_TRUE(memcmp(src, dst, len) == 0);
  }
}

TEST(STRING_TEST, strcpy_align) {
  RunSrcDstBufferAlignTest(LARGE, DoStrcpyTest);
}

TEST(STRING_TEST, strcpy_overread) {
  RunSrcDstBufferOverreadTest(DoStrcpyTest);
}

#if defined(STRLCPY_SUPPORTED)
static void DoStrlcpyTest(uint8_t* src, uint8_t* dst, size_t len) {
  if (len >= 1) {
    memset(src, (32 + (len % 96)), len - 1);
    src[len-1] = '\0';
    memset(dst, 0, len);
    ASSERT_EQ(len-1, strlcpy(reinterpret_cast<char*>(dst),
                             reinterpret_cast<char*>(src), len));
    ASSERT_TRUE(memcmp(src, dst, len) == 0);
  }
}
#endif

TEST(STRING_TEST, strlcpy_align) {
#if defined(STRLCPY_SUPPORTED)
  RunSrcDstBufferAlignTest(LARGE, DoStrlcpyTest);
#else
  GTEST_SKIP() << "strlcpy not available";
#endif
}

TEST(STRING_TEST, strlcpy_overread) {
#if defined(STRLCPY_SUPPORTED)
  RunSrcDstBufferOverreadTest(DoStrlcpyTest);
#else
  GTEST_SKIP() << "strlcpy not available";
#endif
}


static void DoStpcpyTest(uint8_t* src, uint8_t* dst, size_t len) {
  if (len >= 1) {
    memset(src, (32 + (len % 96)), len - 1);
    src[len-1] = '\0';
    memset(dst, 0, len);
    ASSERT_EQ(dst+len-1, reinterpret_cast<uint8_t*>(stpcpy(reinterpret_cast<char*>(dst),
                                                           reinterpret_cast<char*>(src))));
    ASSERT_TRUE(memcmp(src, dst, len) == 0);
  }
}

TEST(STRING_TEST, stpcpy_align) {
  RunSrcDstBufferAlignTest(LARGE, DoStpcpyTest);
}

TEST(STRING_TEST, stpcpy_overread) {
  RunSrcDstBufferOverreadTest(DoStpcpyTest);
}

// Use our own incrementer to cut down on the total number of calls.
static size_t LargeSetIncrement(size_t len) {
  if (len >= 4096) {
    return 4096;
  } else if (len >= 1024) {
    return 1024;
  } else if (len >= 256) {
    return 256;
  }
  return 1;
}

#define STRCAT_DST_LEN  64

static void DoStrcatTest(uint8_t* src, uint8_t* dst, size_t len) {
  if (len >= 1) {
    int value = 32 + (len % 96);
    memset(src, value, len - 1);
    src[len-1] = '\0';

    if (len >= STRCAT_DST_LEN) {
      // Create a small buffer for doing quick compares in each loop.
      uint8_t cmp_buf[STRCAT_DST_LEN];
      // Make sure dst string contains a different value then the src string.
      int value2 = 32 + (value + 2) % 96;
      memset(cmp_buf, value2, sizeof(cmp_buf));

      for (size_t i = 1; i <= STRCAT_DST_LEN;) {
        memset(dst, value2, i-1);
        memset(dst+i-1, 0, len-i);
        src[len-i] = '\0';
        ASSERT_EQ(dst, reinterpret_cast<uint8_t*>(strcat(reinterpret_cast<char*>(dst),
                                                         reinterpret_cast<char*>(src))));
        ASSERT_TRUE(memcmp(dst, cmp_buf, i-1) == 0);
        ASSERT_TRUE(memcmp(src, dst+i-1, len-i+1) == 0);
        // This is an expensive loop, so don't loop through every value,
        // get to a certain size and then start doubling.
        if (i < 16) {
          i++;
        } else {
          i <<= 1;
        }
      }
    } else {
      dst[0] = '\0';
      ASSERT_EQ(dst, reinterpret_cast<uint8_t*>(strcat(reinterpret_cast<char*>(dst),
                                                       reinterpret_cast<char*>(src))));
      ASSERT_TRUE(memcmp(src, dst, len) == 0);
    }
  }
}

TEST(STRING_TEST, strcat_align) {
  RunSrcDstBufferAlignTest(MEDIUM, DoStrcatTest, LargeSetIncrement);
}

TEST(STRING_TEST, strcat_overread) {
  RunSrcDstBufferOverreadTest(DoStrcatTest);
}

#if defined(STRLCAT_SUPPORTED)
static void DoStrlcatTest(uint8_t* src, uint8_t* dst, size_t len) {
  if (len >= 1) {
    int value = 32 + (len % 96);
    memset(src, value, len - 1);
    src[len-1] = '\0';

    if (len >= STRCAT_DST_LEN) {
      // Create a small buffer for doing quick compares in each loop.
      uint8_t cmp_buf[STRCAT_DST_LEN];
      // Make sure dst string contains a different value then the src string.
      int value2 = 32 + (value + 2) % 96;
      memset(cmp_buf, value2, sizeof(cmp_buf));

      for (size_t i = 1; i <= STRCAT_DST_LEN;) {
        memset(dst, value2, i-1);
        memset(dst+i-1, 0, len-i);
        src[len-i] = '\0';
        ASSERT_EQ(len-1, strlcat(reinterpret_cast<char*>(dst),
                                 reinterpret_cast<char*>(src), len));
        ASSERT_TRUE(memcmp(dst, cmp_buf, i-1) == 0);
        ASSERT_TRUE(memcmp(src, dst+i-1, len-i+1) == 0);
        // This is an expensive loop, so don't loop through every value,
        // get to a certain size and then start doubling.
        if (i < 16) {
          i++;
        } else {
          i <<= 1;
        }
      }
    } else {
      dst[0] = '\0';
      ASSERT_EQ(len-1, strlcat(reinterpret_cast<char*>(dst),
                               reinterpret_cast<char*>(src), len));
      ASSERT_TRUE(memcmp(src, dst, len) == 0);
    }
  }
}
#endif

TEST(STRING_TEST, strlcat_align) {
#if defined(STRLCAT_SUPPORTED)
  RunSrcDstBufferAlignTest(MEDIUM, DoStrlcatTest, LargeSetIncrement);
#else
  GTEST_SKIP() << "strlcat not available";
#endif
}

TEST(STRING_TEST, strlcat_overread) {
#if defined(STRLCAT_SUPPORTED)
  RunSrcDstBufferOverreadTest(DoStrlcatTest);
#else
  GTEST_SKIP() << "strlcat not available";
#endif
}

static void DoStrcmpTest(uint8_t* buf1, uint8_t* buf2, size_t len) {
  if (len >= 1) {
    memset(buf1, (32 + (len % 96)), len - 1);
    buf1[len-1] = '\0';
    memset(buf2, (32 + (len % 96)), len - 1);
    buf2[len-1] = '\0';
    ASSERT_EQ(0, strcmp(reinterpret_cast<char*>(buf1),
                        reinterpret_cast<char*>(buf2)));
  }
}

static void DoStrcmpFailTest(uint8_t* buf1, uint8_t* buf2, size_t len1, size_t len2) {
  // Do string length differences.
  int c = (32 + (len1 % 96));
  memset(buf1, c, len1 - 1);
  buf1[len1-1] = '\0';
  memset(buf2, c, len2 - 1);
  buf2[len2-1] = '\0';
  ASSERT_NE(0, strcmp(reinterpret_cast<char*>(buf1),
                      reinterpret_cast<char*>(buf2)));

  // Do single character differences.
  size_t len;
  if (len1 > len2) {
    len = len2;
  } else {
    len = len1;
  }
  // Need at least a two character buffer to do this test.
  if (len > 1) {
    buf1[len-1] = '\0';
    buf2[len-1] = '\0';
    int diff_c = (c + 1) % 96;

    buf1[len-2] = diff_c;
    ASSERT_NE(0, strcmp(reinterpret_cast<char*>(buf1),
                        reinterpret_cast<char*>(buf2)));

    buf1[len-2] = c;
    buf2[len-2] = diff_c;
    ASSERT_NE(0, strcmp(reinterpret_cast<char*>(buf1),
                        reinterpret_cast<char*>(buf2)));
  }
}

TEST(STRING_TEST, strcmp_align) {
  RunCmpBufferAlignTest(MEDIUM, DoStrcmpTest, DoStrcmpFailTest, LargeSetIncrement);
}

TEST(STRING_TEST, strcmp_overread) {
  RunCmpBufferOverreadTest(DoStrcmpTest, DoStrcmpFailTest);
}

static void DoMemcmpTest(uint8_t* buf1, uint8_t* buf2, size_t len) {
  memset(buf1, len+1, len);
  memset(buf2, len+1, len);
  ASSERT_EQ(0, memcmp(buf1, buf2, len));
}

static void DoMemcmpFailTest(uint8_t* buf1, uint8_t* buf2, size_t len1, size_t len2) {
  size_t len;
  if (len1 > len2) {
    len = len2;
  } else {
    len = len1;
  }

  memset(buf1, len2+1, len);
  buf1[len-1] = len2;
  memset(buf2, len2+1, len);
  ASSERT_NE(0, memcmp(buf1, buf2, len));

  buf1[len-1] = len2+1;
  buf2[len-1] = len2;
  ASSERT_NE(0, memcmp(buf1, buf2, len));
}

TEST(STRING_TEST, memcmp_align) {
  RunCmpBufferAlignTest(MEDIUM, DoMemcmpTest, DoMemcmpFailTest, LargeSetIncrement);
}

TEST(STRING_TEST, memcmp_overread) {
  RunCmpBufferOverreadTest(DoMemcmpTest, DoMemcmpFailTest);
}

static void DoMemchrTest(uint8_t* buf, size_t len) {
  if (len >= 1) {
    int value = len % 128;
    int search_value = (len % 128) + 1;
    memset(buf, value, len);
    // The buffer does not contain the search value.
    ASSERT_EQ(nullptr, memchr(buf, search_value, len));
    if (len >= 2) {
      buf[0] = search_value;
      // The search value is the first element in the buffer.
      ASSERT_EQ(&buf[0], memchr(buf, search_value, len));

      buf[0] = value;
      buf[len - 1] = search_value;
      // The search value is the last element in the buffer.
      ASSERT_EQ(&buf[len - 1], memchr(buf, search_value, len));
    }
  }
}

TEST(STRING_TEST, memchr_align) {
  RunSingleBufferAlignTest(MEDIUM, DoMemchrTest);
}

TEST(STRING_TEST, memchr_overread) {
  RunSingleBufferOverreadTest(DoMemchrTest);
}

static void DoStrchrTest(uint8_t* buf, size_t len) {
  if (len >= 1) {
    char value = 32 + (len % 96);
    char search_value = 33 + (len % 96);
    memset(buf, value, len - 1);
    buf[len - 1] = '\0';
    // The buffer does not contain the search value.
    ASSERT_EQ(nullptr, strchr(reinterpret_cast<char*>(buf), search_value));
    // Search for the special '\0' character.
    ASSERT_EQ(reinterpret_cast<char*>(&buf[len - 1]), strchr(reinterpret_cast<char*>(buf), '\0'));
    if (len >= 2) {
      buf[0] = search_value;
      // The search value is the first element in the buffer.
      ASSERT_EQ(reinterpret_cast<char*>(&buf[0]), strchr(reinterpret_cast<char*>(buf),
                                                         search_value));

      buf[0] = value;
      buf[len - 2] = search_value;
      // The search value is the second to last element in the buffer.
      // The last element is the '\0' character.
      ASSERT_EQ(reinterpret_cast<char*>(&buf[len - 2]), strchr(reinterpret_cast<char*>(buf),
                                                               search_value));
    }
  }
}

TEST(STRING_TEST, strchr_align) {
  RunSingleBufferAlignTest(MEDIUM, DoStrchrTest);
}

TEST(STRING_TEST, strchr_overread) {
  RunSingleBufferOverreadTest(DoStrchrTest);
}

static void DoStrrchrTest(uint8_t* buf, size_t len) {
  if (len >= 1) {
    char value = 32 + (len % 96);
    char search_value = 33 + (len % 96);
    memset(buf, value, len - 1);
    buf[len - 1] = '\0';
    // The buffer does not contain the search value.
    ASSERT_EQ(nullptr, strrchr(reinterpret_cast<char*>(buf), search_value));
    // Search for the special '\0' character.
    ASSERT_EQ(reinterpret_cast<char*>(&buf[len - 1]), strrchr(reinterpret_cast<char*>(buf), '\0'));
    if (len >= 2) {
      buf[0] = search_value;
      // The search value is the first element in the buffer.
      ASSERT_EQ(reinterpret_cast<char*>(&buf[0]), strrchr(reinterpret_cast<char*>(buf),
                                                          search_value));

      buf[0] = value;
      buf[len - 2] = search_value;
      // The search value is the second to last element in the buffer.
      // The last element is the '\0' character.
      ASSERT_EQ(reinterpret_cast<char*>(&buf[len - 2]), strrchr(reinterpret_cast<char*>(buf),
                                                                search_value));
    }
  }
}

TEST(STRING_TEST, strrchr_align) {
  RunSingleBufferAlignTest(MEDIUM, DoStrrchrTest);
}

TEST(STRING_TEST, strrchr_overread) {
  RunSingleBufferOverreadTest(DoStrrchrTest);
}

#if !defined(ANDROID_HOST_MUSL)
static void TestBasename(const char* in, const char* expected_out) {
  errno = 0;
  const char* out = basename(in);
  ASSERT_STREQ(expected_out, out) << in;
  ASSERT_ERRNO(0) << in;
}
#endif

TEST(STRING_TEST, __gnu_basename) {
#if !defined(ANDROID_HOST_MUSL)
  TestBasename("", "");
  TestBasename("/usr/lib", "lib");
  TestBasename("/usr/", "");
  TestBasename("usr", "usr");
  TestBasename("/", "");
  TestBasename(".", ".");
  TestBasename("..", "..");
  TestBasename("///", "");
  TestBasename("//usr//lib//", "");
#else
  GTEST_SKIP() << "musl doesn't have GNU basename";
#endif
}

TEST(STRING_TEST, strnlen_147048) {
  // https://code.google.com/p/android/issues/detail?id=147048
  char stack_src[64] = {0};
  EXPECT_EQ(0U, strnlen(stack_src, 1024*1024*1024));
  char* heap_src = new char[1];
  *heap_src = '\0';
  EXPECT_EQ(0U, strnlen(heap_src, 1024*1024*1024));
  delete[] heap_src;
}

TEST(STRING_TEST, strnlen_74741) {
  ASSERT_EQ(4U, strnlen("test", SIZE_MAX));
}

TEST(STRING_TEST, mempcpy) {
  char dst[6];
  ASSERT_EQ(&dst[4], reinterpret_cast<char*>(mempcpy(dst, "hello", 4)));
}

// clang depends on the fact that a memcpy where src and dst is the same
// still operates correctly. This test verifies that this assumption
// holds true.
// See https://llvm.org/bugs/show_bug.cgi?id=11763 for more information.
static std::vector<uint8_t> g_memcpy_same_buffer;

static void DoMemcpySameTest(uint8_t* buffer, size_t len) {
  memcpy(buffer, g_memcpy_same_buffer.data(), len);
  ASSERT_EQ(buffer, memcpy(buffer, buffer, len));
  ASSERT_TRUE(memcmp(buffer, g_memcpy_same_buffer.data(), len) == 0);
}

TEST(STRING_TEST, memcpy_src_dst_same) {
  g_memcpy_same_buffer.resize(MEDIUM);
  for (size_t i = 0; i < MEDIUM; i++) {
    g_memcpy_same_buffer[i] = i;
  }
  RunSingleBufferAlignTest(MEDIUM, DoMemcpySameTest);
}

TEST(STRING_TEST, memmem_strstr_empty_needle) {
  const char* some_haystack = "haystack";
  const char* empty_haystack = "";

  ASSERT_EQ(some_haystack, memmem(some_haystack, 8, "", 0));
  ASSERT_EQ(empty_haystack, memmem(empty_haystack, 0, "", 0));

  ASSERT_EQ(some_haystack, strstr(some_haystack, ""));
  ASSERT_EQ(empty_haystack, strstr(empty_haystack, ""));
}

TEST(STRING_TEST, memmem_smoke) {
  const char haystack[] = "big\0daddy/giant\0haystacks!";

  // The current memmem() implementation has special cases for needles of
  // lengths 0, 1, 2, 3, and 4, plus a long needle case. We test matches at the
  // beginning, middle, and end of the haystack.

  ASSERT_EQ(haystack + 0, memmem(haystack, sizeof(haystack), "", 0));

  ASSERT_EQ(haystack + 0, memmem(haystack, sizeof(haystack), "b", 1));
  ASSERT_EQ(haystack + 0, memmem(haystack, sizeof(haystack), "bi", 2));
  ASSERT_EQ(haystack + 0, memmem(haystack, sizeof(haystack), "big", 3));
  ASSERT_EQ(haystack + 0, memmem(haystack, sizeof(haystack), "big\0", 4));
  ASSERT_EQ(haystack + 0, memmem(haystack, sizeof(haystack), "big\0d", 5));

  ASSERT_EQ(haystack + 2, memmem(haystack, sizeof(haystack), "g", 1));
  ASSERT_EQ(haystack + 10, memmem(haystack, sizeof(haystack), "gi", 2));
  ASSERT_EQ(haystack + 10, memmem(haystack, sizeof(haystack), "gia", 3));
  ASSERT_EQ(haystack + 10, memmem(haystack, sizeof(haystack), "gian", 4));
  ASSERT_EQ(haystack + 10, memmem(haystack, sizeof(haystack), "giant", 5));

  ASSERT_EQ(haystack + 25, memmem(haystack, sizeof(haystack), "!", 1));
  ASSERT_EQ(haystack + 24, memmem(haystack, sizeof(haystack), "s!", 2));
  ASSERT_EQ(haystack + 23, memmem(haystack, sizeof(haystack), "ks!", 3));
  ASSERT_EQ(haystack + 22, memmem(haystack, sizeof(haystack), "cks!", 4));
  ASSERT_EQ(haystack + 21, memmem(haystack, sizeof(haystack), "acks!", 5));
}

TEST(STRING_TEST, strstr_smoke) {
  const char* haystack = "big daddy/giant haystacks!";

  // The current strstr() implementation has special cases for needles of
  // lengths 0, 1, 2, 3, and 4, plus a long needle case. We test matches at the
  // beginning, middle, and end of the haystack.

  ASSERT_EQ(haystack + 0, strstr(haystack, ""));

  ASSERT_EQ(haystack + 0, strstr(haystack, "b"));
  ASSERT_EQ(haystack + 0, strstr(haystack, "bi"));
  ASSERT_EQ(haystack + 0, strstr(haystack, "big"));
  ASSERT_EQ(haystack + 0, strstr(haystack, "big "));
  ASSERT_EQ(haystack + 0, strstr(haystack, "big d"));

  ASSERT_EQ(haystack + 2, strstr(haystack, "g"));
  ASSERT_EQ(haystack + 10, strstr(haystack, "gi"));
  ASSERT_EQ(haystack + 10, strstr(haystack, "gia"));
  ASSERT_EQ(haystack + 10, strstr(haystack, "gian"));
  ASSERT_EQ(haystack + 10, strstr(haystack, "giant"));

  ASSERT_EQ(haystack + 25, strstr(haystack, "!"));
  ASSERT_EQ(haystack + 24, strstr(haystack, "s!"));
  ASSERT_EQ(haystack + 23, strstr(haystack, "ks!"));
  ASSERT_EQ(haystack + 22, strstr(haystack, "cks!"));
  ASSERT_EQ(haystack + 21, strstr(haystack, "acks!"));
}

TEST(STRING_TEST, strcasestr_smoke) {
  const char* haystack = "bIg dAdDy/gIaNt hAyStAcKs";
  ASSERT_EQ(haystack, strcasestr(haystack, ""));
  ASSERT_EQ(haystack + 0, strcasestr(haystack, "B"));
  ASSERT_EQ(haystack + 1, strcasestr(haystack, "i"));
  ASSERT_EQ(haystack + 4, strcasestr(haystack, "Da"));
}

TEST(STRING_TEST, strcoll_smoke) {
  ASSERT_TRUE(strcoll("aab", "aac") < 0);
  ASSERT_TRUE(strcoll("aab", "aab") == 0);
  ASSERT_TRUE(strcoll("aac", "aab") > 0);
}

TEST(STRING_TEST, strcoll_l_smoke) {
  // bionic just forwards to strcoll(3).
  ASSERT_TRUE(strcoll_l("aab", "aac", LC_GLOBAL_LOCALE) < 0);
  ASSERT_TRUE(strcoll_l("aab", "aab", LC_GLOBAL_LOCALE) == 0);
  ASSERT_TRUE(strcoll_l("aac", "aab", LC_GLOBAL_LOCALE) > 0);
}

TEST(STRING_TEST, strxfrm_smoke) {
  const char* src1 = "aab";
  char dst1[16] = {};
  // Dry run.
  ASSERT_EQ(strxfrm(dst1, src1, 0), 3U);
  ASSERT_STREQ(dst1, "");
  // Really do it.
  ASSERT_EQ(strxfrm(dst1, src1, sizeof(dst1)), 3U);

  const char* src2 = "aac";
  char dst2[16] = {};
  // Dry run.
  ASSERT_EQ(strxfrm(dst2, src2, 0), 3U);
  ASSERT_STREQ(dst2, "");
  // Really do it.
  ASSERT_EQ(strxfrm(dst2, src2, sizeof(dst2)), 3U);

  // The "transform" of two different strings should cause different outputs.
  ASSERT_TRUE(strcmp(dst1, dst2) < 0);
}

TEST(STRING_TEST, strxfrm_l_smoke) {
  // bionic just forwards to strxfrm(3), so this is a subset of the
  // strxfrm test.
  const char* src1 = "aab";
  char dst1[16] = {};
  ASSERT_EQ(strxfrm_l(dst1, src1, 0, LC_GLOBAL_LOCALE), 3U);
  ASSERT_STREQ(dst1, "");
  ASSERT_EQ(strxfrm_l(dst1, src1, sizeof(dst1), LC_GLOBAL_LOCALE), 3U);
}

TEST(STRING_TEST, memccpy_smoke) {
  char dst[32];

  memset(dst, 0, sizeof(dst));
  char* p = static_cast<char*>(memccpy(dst, "hello world", ' ', 32));
  ASSERT_STREQ("hello ", dst);
  ASSERT_EQ(ptrdiff_t(6), p - dst);

  memset(dst, 0, sizeof(dst));
  ASSERT_EQ(nullptr, memccpy(dst, "hello world", ' ', 4));
  ASSERT_STREQ("hell", dst);
}

TEST(STRING_TEST, memset_explicit_smoke) {
#if defined(__BIONIC__)
  // We can't reliably test that the compiler won't optimize out calls to
  // memset_explicit(), but we can at least check that it behaves like memset.
  char buf[32];
  memset_explicit(buf, 'x', sizeof(buf));
  ASSERT_TRUE(memcmp(buf, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", sizeof(buf)) == 0);
#else
  GTEST_SKIP() << "memset_explicit not available";
#endif
}

TEST(STRING_TEST, strerrorname_np) {
#if defined(__BIONIC__)
  ASSERT_STREQ("0", strerrorname_np(0));
  ASSERT_STREQ("EINVAL", strerrorname_np(EINVAL));
  ASSERT_STREQ("ENOSYS", strerrorname_np(ENOSYS));

  ASSERT_EQ(nullptr, strerrorname_np(-1));
  ASSERT_EQ(nullptr, strerrorname_np(666));
#else
  GTEST_SKIP() << "strerrorname_np not available";
#endif
}
```