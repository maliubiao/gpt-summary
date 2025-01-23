Response:
The user wants a breakdown of the C code provided, specifically looking for:

1. **Functionality:** What does this code do?
2. **Reversing Relevance:** How does it relate to reverse engineering? Provide examples.
3. **Low-Level Details:**  Connections to binary, Linux/Android kernel, and frameworks. Provide examples.
4. **Logical Inference:**  Hypothetical inputs and outputs based on the logic.
5. **Common User Errors:** Mistakes users might make when using this code.
6. **User Path:** How a user might end up interacting with this code (debugging context).
7. **Summary:**  A concise overview of the code's purpose.

This is the 8th part of 11, suggesting this file is part of a larger test suite for Frida's GumJS component. The file name "script.c" and the content strongly indicate that it tests the JavaScript API provided by Frida for interacting with a running process.

**Plan:**

1. **Analyze each `TESTCASE` function:** Each `TESTCASE` represents a specific feature or scenario being tested. I'll break down what each test does.
2. **Identify Reversing Connections:**  Focus on features like `Interceptor`, memory scanning, and manipulation. These are core to dynamic instrumentation and reverse engineering.
3. **Pinpoint Low-Level Aspects:**  Look for interactions with memory management (allocation, protection), patching, and direct memory access. This links to OS and architecture concepts.
4. **Infer Inputs/Outputs:**  For tests involving specific operations, I'll consider the provided data and the expected outcomes based on the Frida API.
5. **Anticipate User Errors:** Consider common mistakes when using dynamic instrumentation, like incorrect addresses, sizes, or callback functions.
6. **Construct User Path:** Think about the typical workflow of using Frida: attaching to a process, writing a script, and observing the effects.
7. **Synthesize a Summary:** Condense the overall functionality revealed by these test cases.
```python
这是目录为frida/subprojects/frida-gum/tests/gumjs/script.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能,
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共11部分，请归纳一下它的功能

"""
m_script_unload_sync (fixture->script, NULL);

  COMPILE_AND_LOAD_SCRIPT (
      "const origPtr = ptr(" GUM_PTR_CONST ");"
      "const orig = Interceptor.replaceFast(" GUM_PTR_CONST ", " GUM_PTR_CONST
        ");"
      "origPtr.writePointer(orig);",
      &target_function_original,
      target_function_int,
      target_function_int_replacement);

  g_timer_reset (timer);
  for (i = 0; i != 1000000; i++)
    g_assert_cmpint (target_function_int (7), ==, 1652);
  duration_fast = g_timer_elapsed (timer, NULL);

  g_timer_destroy (timer);

  g_print ("<duration_fast=%f duration_default=%f ratio=%f> ",
      duration_fast,
      duration_default,
      duration_fast / duration_default);
}

GUM_NOINLINE static int
target_function_int_replacement (int arg)
{
  if (target_function_original == NULL)
    return 1337;
  else
    return 1337 + target_function_original (arg);
}

TESTCASE (interceptor_on_enter_performance)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "  }"
      "});", target_function_int);

#if 1
  measure_target_function_int_overhead ();
#else
  while (TRUE)
    target_function_int (7);
#endif
}

TESTCASE (interceptor_on_leave_performance)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onLeave(retval) {"
      "  }"
      "});", target_function_int);

#if 1
  measure_target_function_int_overhead ();
#else
  while (TRUE)
    target_function_int (7);
#endif
}

TESTCASE (interceptor_on_enter_and_leave_performance)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "  },"
      "  onLeave(retval) {"
      "  }"
      "});", target_function_int);

#if 1
  measure_target_function_int_overhead ();
#else
  while (TRUE)
### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/gumjs/script.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共11部分，请归纳一下它的功能
```

### 源代码
```c
m_script_unload_sync (fixture->script, NULL);

  COMPILE_AND_LOAD_SCRIPT (
      "const origPtr = ptr(" GUM_PTR_CONST ");"
      "const orig = Interceptor.replaceFast(" GUM_PTR_CONST ", " GUM_PTR_CONST
        ");"
      "origPtr.writePointer(orig);",
      &target_function_original,
      target_function_int,
      target_function_int_replacement);

  g_timer_reset (timer);
  for (i = 0; i != 1000000; i++)
    g_assert_cmpint (target_function_int (7), ==, 1652);
  duration_fast = g_timer_elapsed (timer, NULL);

  g_timer_destroy (timer);

  g_print ("<duration_fast=%f duration_default=%f ratio=%f> ",
      duration_fast,
      duration_default,
      duration_fast / duration_default);
}

GUM_NOINLINE static int
target_function_int_replacement (int arg)
{
  if (target_function_original == NULL)
    return 1337;
  else
    return 1337 + target_function_original (arg);
}

TESTCASE (interceptor_on_enter_performance)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "  }"
      "});", target_function_int);

#if 1
  measure_target_function_int_overhead ();
#else
  while (TRUE)
    target_function_int (7);
#endif
}

TESTCASE (interceptor_on_leave_performance)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onLeave(retval) {"
      "  }"
      "});", target_function_int);

#if 1
  measure_target_function_int_overhead ();
#else
  while (TRUE)
    target_function_int (7);
#endif
}

TESTCASE (interceptor_on_enter_and_leave_performance)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "  },"
      "  onLeave(retval) {"
      "  }"
      "});", target_function_int);

#if 1
  measure_target_function_int_overhead ();
#else
  while (TRUE)
    target_function_int (7);
#endif
}

static void
measure_target_function_int_overhead (void)
{
  GTimer * timer;
  guint i, n;
  gdouble measurement[1000], t_min, t_max, t_median;

  n = G_N_ELEMENTS (measurement);

  timer = g_timer_new ();

  for (i = 0; i != n; i++)
  {
    target_function_int (7);
  }

  for (i = 0; i != n; i++)
  {
    g_timer_reset (timer);
    target_function_int (7);
    measurement[i] = g_timer_elapsed (timer, NULL);
  }

  qsort (measurement, n, sizeof (gdouble), compare_measurements);

  t_min = measurement[0];
  t_max = measurement[n - 1];
  g_assert (n % 2 == 0);
  t_median = (measurement[n / 2] + measurement[(n / 2) - 1]) / 2.0;

  g_print ("<min: %.1f us, max: %.1f us, median: %.1f us> ",
      t_min * (gdouble) G_USEC_PER_SEC,
      t_max * (gdouble) G_USEC_PER_SEC,
      t_median * (gdouble) G_USEC_PER_SEC);

  g_timer_destroy (timer);
}

static int
compare_measurements (gconstpointer element_a,
                      gconstpointer element_b)
{
  const gdouble a = *(const gdouble *) element_a;
  const gdouble b = *(const gdouble *) element_b;

  if (a > b)
    return 1;

  if (a < b)
    return -1;

  return 0;
}

TESTCASE (memory_can_be_scanned_with_pattern_string)
{
  guint8 haystack1[] = { 0x01, 0x02, 0x13, 0x37, 0x03, 0x13, 0x37 };
  gchar haystack2[] = "Hello world, hello world, I said.";

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scan(" GUM_PTR_CONST ", 7, '13 37', {"
        "onMatch(address, size) {"
        "  send('onMatch offset=' + address.sub(" GUM_PTR_CONST
             ").toInt32() + ' size=' + size);"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});", haystack1, haystack1);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=2 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=5 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scan(" GUM_PTR_CONST ", uint64(7), '13 37', {"
        "onMatch(address, size) {"
        "  send('onMatch offset=' + address.sub(" GUM_PTR_CONST
             ").toInt32() + ' size=' + size);"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});", haystack1, haystack1);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=2 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=5 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "const regex = /[Hh]ello\\sworld/.toString();"
      "Memory.scan(" GUM_PTR_CONST ", 33, regex, {"
        "onMatch(address, size) {"
        "  send('onMatch offset=' + address.sub(" GUM_PTR_CONST
             ").toInt32() + ' size=' + size);"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});", haystack2, haystack2);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=0 size=11\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=13 size=11\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

TESTCASE (memory_can_be_scanned_with_match_pattern_object)
{
  guint8 haystack1[] = { 0x01, 0x02, 0x13, 0x37, 0x03, 0x13, 0x37 };
  gchar haystack2[] = "Hello world, hello world, I said.";

  COMPILE_AND_LOAD_SCRIPT (
      "const pattern = new MatchPattern('13 37');"
      "Memory.scan(" GUM_PTR_CONST ", 7, pattern, {"
        "onMatch(address, size) {"
        "  send('onMatch offset=' + address.sub(" GUM_PTR_CONST
             ").toInt32() + ' size=' + size);"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});", haystack1, haystack1);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=2 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=5 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "const pattern = new MatchPattern('13 37');"
      "Memory.scan(" GUM_PTR_CONST ", uint64(7), pattern, {"
        "onMatch(address, size) {"
        "  send('onMatch offset=' + address.sub(" GUM_PTR_CONST
             ").toInt32() + ' size=' + size);"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});", haystack1, haystack1);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=2 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=5 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "const pattern = new MatchPattern(/[Hh]ello\\sworld/.toString());"
      "Memory.scan(" GUM_PTR_CONST ", 33, pattern, {"
        "onMatch(address, size) {"
        "  send('onMatch offset=' + address.sub(" GUM_PTR_CONST
             ").toInt32() + ' size=' + size);"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});", haystack2, haystack2);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=0 size=11\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=13 size=11\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  haystack2[7] = 0xd1;

  COMPILE_AND_LOAD_SCRIPT (
      "const pattern = new MatchPattern(/Hello/.toString());"
      "Memory.scan(" GUM_PTR_CONST ", 33, pattern, {"
        "onMatch(address, size) {"
        "  send('onMatch offset=' + address.sub(" GUM_PTR_CONST
             ").toInt32() + ' size=' + size);"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});", haystack2, haystack2);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=0 size=5\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

TESTCASE (memory_can_be_scanned_synchronously)
{
  guint8 haystack[] = { 0x01, 0x02, 0x13, 0x37, 0x03, 0x13, 0x37 };

  COMPILE_AND_LOAD_SCRIPT (
      "for (const match of Memory.scanSync(" GUM_PTR_CONST ", 7, '13 37')) {"
      "  send(`match offset=${match.address.sub(" GUM_PTR_CONST ").toInt32()} "
          "size=${match.size}`);"
      "}"
      "send('done');",
      haystack, haystack);
  EXPECT_SEND_MESSAGE_WITH ("\"match offset=2 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"match offset=5 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"done\"");

  COMPILE_AND_LOAD_SCRIPT (
      "for (const match of Memory.scanSync(" GUM_PTR_CONST ", uint64(7), "
          "'13 37')) {"
      "  send(`match offset=${match.address.sub(" GUM_PTR_CONST ").toInt32()} "
          "size=${match.size}`);"
      "}"
      "send('done');",
      haystack, haystack);
  EXPECT_SEND_MESSAGE_WITH ("\"match offset=2 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"match offset=5 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"done\"");
}

TESTCASE (memory_can_be_scanned_asynchronously)
{
  guint8 haystack[] = { 0x01, 0x02, 0x13, 0x37, 0x03, 0x13, 0x37 };

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scan(" GUM_PTR_CONST ", 7, '13 37', {"
      "  onMatch(address, size) {"
      "    send('onMatch offset=' + address.sub(" GUM_PTR_CONST ").toInt32()"
      "      + ' size=' + size);"
      "  }"
      "})"
      ".catch(e => console.error(e.message))"
      ".then(() => send('DONE'));", haystack, haystack);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=2 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=5 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"DONE\"");

  if (!check_exception_handling_testable ())
    return;

  COMPILE_AND_LOAD_SCRIPT (
      "async function run() {"
      "  try {"
      "    await Memory.scan(ptr(0xdead), 7, '13 37', {"
      "      onMatch(address, size) {}"
      "    });"
      "  } catch (e) {"
      "    send(e.message);"
      "  }"
      "}"
      "run();"
  );
  EXPECT_SEND_MESSAGE_WITH ("\"access violation accessing 0xdead\"");
}

TESTCASE (memory_scan_should_be_interruptible)
{
  guint8 haystack[] = { 0x01, 0x02, 0x13, 0x37, 0x03, 0x13, 0x37 };
  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scan(" GUM_PTR_CONST ", 7, '13 37', {"
        "onMatch(address, size) {"
        "  send('onMatch offset=' + address.sub(" GUM_PTR_CONST
             ").toInt32() + ' size=' + size);"
        "  return 'stop';"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});", haystack, haystack);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=2 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

TESTCASE (memory_scan_handles_unreadable_memory)
{
  if (!check_exception_handling_testable ())
    return;

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scan(ptr(\"1328\"), 7, '13 37', {"
        "onMatch(address, size) {"
        "  send('onMatch');"
        "},"
        "onError(message) {"
        "  send('onError: ' + message);"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("\"onError: access violation accessing 0x530\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "try {"
        "Memory.scanSync(ptr(\"1328\"), 7, '13 37');"
      "} catch (e) {"
        "send(e.message);"
      "}");
  EXPECT_SEND_MESSAGE_WITH ("\"access violation accessing 0x530\"");
}

TESTCASE (memory_scan_handles_bad_arguments)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scan(0x1337, 7, '13 37', {"
      "  onMatch(address, size) {}, onComplete() {}"
      "});");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: expected a pointer");

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scan(ptr(0x1337), -7, '13 37', {"
      "  onMatch(address, size) {}, onComplete() {}"
      "});");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: expected an unsigned integer");

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scan(ptr(0x1337), 7, 0xbadcafe, {"
      "  onMatch(address, size) {},"
      "  onComplete() {}"
      "});");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: expected either a pattern string or a MatchPattern object");

  COMPILE_AND_LOAD_SCRIPT (
    "Memory.scan(ptr(0x1337), 7, 'bad pattern', {"
    "  onMatch(addres, size) {}"
    "});"
  );
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: invalid match pattern");

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scan(ptr(0x1337), 7, '13 37', { onComplete() {} });"
  );
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: expected a callback value");
}

TESTCASE (memory_access_can_be_monitored)
{
  volatile guint8 * a, * b;
  guint page_size;

  if (!check_exception_handling_testable ())
    return;

  a = gum_alloc_n_pages (2, GUM_PAGE_RW);
  b = gum_alloc_n_pages (1, GUM_PAGE_RW);
  page_size = gum_query_page_size ();

  COMPILE_AND_LOAD_SCRIPT (
      "MemoryAccessMonitor.enable([{ base: " GUM_PTR_CONST ", size: %u },"
        "{ base: " GUM_PTR_CONST ", size: %u }], {"
        "onAccess(details) {"
          "send([details.operation, !!details.from, details.address,"
            "details.rangeIndex, details.pageIndex, details.pagesCompleted,"
            "details.pagesTotal]);"
        "}"
      "});",
      a + page_size, page_size, b, page_size);
  EXPECT_NO_MESSAGES ();

  a[0] = 1;
  a[page_size - 1] = 2;
  EXPECT_NO_MESSAGES ();

  a[page_size] = 3;
  EXPECT_SEND_MESSAGE_WITH ("[\"write\",true,\"0x%" G_GSIZE_MODIFIER "x\","
      "0,0,1,2]", GPOINTER_TO_SIZE (a + page_size));

  a[0] = b[page_size - 1];
  EXPECT_SEND_MESSAGE_WITH ("[\"read\",true,\"0x%" G_GSIZE_MODIFIER "x\","
      "1,0,2,2]", GPOINTER_TO_SIZE (b + page_size - 1));

  gum_free_pages ((gpointer) b);
  gum_free_pages ((gpointer) a);
}

TESTCASE (memory_access_can_be_monitored_one_range)
{
  volatile guint8 * a;
  guint page_size;

  if (!check_exception_handling_testable ())
    return;

  a = gum_alloc_n_pages (2, GUM_PAGE_RW);
  page_size = gum_query_page_size ();

  COMPILE_AND_LOAD_SCRIPT (
      "MemoryAccessMonitor.enable({ base: " GUM_PTR_CONST ", size: %u }, {"
        "onAccess(details) {"
          "send([details.operation, !!details.from, details.address,"
            "details.rangeIndex, details.pageIndex, details.pagesCompleted,"
            "details.pagesTotal]);"
        "}"
      "});",
      a + page_size, page_size);
  EXPECT_NO_MESSAGES ();

  a[0] = 1;
  a[page_size - 1] = 2;
  EXPECT_NO_MESSAGES ();

  a[page_size] = 3;
  EXPECT_SEND_MESSAGE_WITH ("[\"write\",true,\"0x%" G_GSIZE_MODIFIER "x\","
      "0,0,1,1]", GPOINTER_TO_SIZE (a + page_size));

  gum_free_pages ((gpointer) a);
}

TESTCASE (pointer_can_be_read)
{
  gpointer val = GSIZE_TO_POINTER (0x1337000);
  COMPILE_AND_LOAD_SCRIPT (
      "send(" GUM_PTR_CONST ".readPointer().toString());", &val);
  EXPECT_SEND_MESSAGE_WITH ("\"0x1337000\"");
}

TESTCASE (pointer_can_be_read_legacy_style)
{
  gpointer val = GSIZE_TO_POINTER (0x1337000);
  COMPILE_AND_LOAD_SCRIPT (
      "send(Memory.readPointer(" GUM_PTR_CONST ").toString());", &val);
  EXPECT_SEND_MESSAGE_WITH ("\"0x1337000\"");
}

TESTCASE (pointer_can_be_written)
{
  gpointer vals[2] = { NULL, NULL };
  COMPILE_AND_LOAD_SCRIPT (
      GUM_PTR_CONST ".writePointer(ptr(\"0x1337000\"))"
      ".add(Process.pointerSize).writePointer(ptr(\"0x1338000\"))",
      vals);
  g_assert_cmphex (GPOINTER_TO_SIZE (vals[0]), ==, 0x1337000);
  g_assert_cmphex (GPOINTER_TO_SIZE (vals[1]), ==, 0x1338000);
}

TESTCASE (pointer_can_be_written_legacy_style)
{
  gpointer val = NULL;
  COMPILE_AND_LOAD_SCRIPT (
      "Memory.writePointer(" GUM_PTR_CONST ", ptr(\"0x1337000\"));", &val);
  g_assert_cmphex (GPOINTER_TO_SIZE (val), ==, 0x1337000);
}

TESTCASE (memory_can_be_allocated_with_byte_granularity)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const p = Memory.alloc(8);"
      "p.writePointer(ptr('1337'));"
      "send(p.readPointer().toInt32() === 1337);");
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "const p = Memory.alloc(uint64(8));"
      "p.writePointer(ptr('1337'));"
      "send(p.readPointer().toInt32() === 1337);");
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "const p = Memory.alloc(5);"
      "send('p', p.readByteArray(5));");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA("\"p\"", "00 00 00 00 00");
}

TESTCASE (memory_can_be_allocated_with_page_granularity)
{
  gsize p;

  COMPILE_AND_LOAD_SCRIPT (
      "const p = Memory.alloc(Process.pageSize);"
      "send(p);");
  p = GPOINTER_TO_SIZE (EXPECT_SEND_MESSAGE_WITH_POINTER ());
  g_assert_cmpuint (p, !=, 0);
  g_assert_cmpuint (p & (gum_query_page_size () - 1), ==, 0);

  COMPILE_AND_LOAD_SCRIPT (
      "const p = Memory.alloc(5);"
      "send('p', p.readByteArray(5));");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA("\"p\"", "00 00 00 00 00");
}

TESTCASE (memory_can_be_allocated_near_address)
{
  gsize p;

  COMPILE_AND_LOAD_SCRIPT (
      "const maxDistance = uint64(NULL.sub(1).toString());"
      "const a = Memory.alloc(Process.pageSize);"
      "const b = Memory.alloc(Process.pageSize, { near: a, maxDistance });"
      "send(b);");
  p = GPOINTER_TO_SIZE (EXPECT_SEND_MESSAGE_WITH_POINTER ());
  g_assert_cmpuint (p, !=, 0);
  g_assert_cmpuint (p & (gum_query_page_size () - 1), ==, 0);

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.alloc(Process.pageSize - 1, { "
          "near: ptr(Process.pageSize), "
          "maxDistance: 12345678 "
      "});");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: size must be a multiple of page size");

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.alloc(Process.pageSize, { near: ptr(Process.pageSize) });");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: missing maxDistance option");
}

TESTCASE (memory_can_be_copied)
{
  const gchar * from = "Hei";
  gchar to[5] = { 0x01, 0x02, 0x03, 0x04, 0x05 };

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.copy(" GUM_PTR_CONST ", " GUM_PTR_CONST ", 3);", to, from);
  g_assert_cmphex (to[0], ==, 'H');
  g_assert_cmphex (to[1], ==, 'e');
  g_assert_cmphex (to[2], ==, 'i');
  g_assert_cmphex (to[3], ==, 0x04);
  g_assert_cmphex (to[4], ==, 0x05);

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.copy(" GUM_PTR_CONST ".add(3), " GUM_PTR_CONST ", uint64(2));",
      to, from);
  g_assert_cmphex (to[0], ==, 'H');
  g_assert_cmphex (to[1], ==, 'e');
  g_assert_cmphex (to[2], ==, 'i');
  g_assert_cmphex (to[3], ==, 'H');
  g_assert_cmphex (to[4], ==, 'e');

  /* TODO: investigate */
#if !(defined (HAVE_LINUX) && defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4)
  if (!gum_process_is_debugger_attached () && !RUNNING_ON_VALGRIND)
  {
    COMPILE_AND_LOAD_SCRIPT (
        "Memory.copy(" GUM_PTR_CONST ", ptr(\"1337\"), 1);", to);
    EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation accessing 0x539");
  }
#endif
}

TESTCASE (memory_can_be_duped)
{
  guint8 buf[3] = { 0x13, 0x37, 0x42 };

  COMPILE_AND_LOAD_SCRIPT (
      "const p = Memory.dup(" GUM_PTR_CONST ", 3);"
      "p.writeU8(0x12);"
      "send('p', p.readByteArray(3));"
      "send('buf', " GUM_PTR_CONST ".readByteArray(3));",
      buf, buf);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"p\"", "12 37 42");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"buf\"", "13 37 42");

  COMPILE_AND_LOAD_SCRIPT (
      "const p = Memory.dup(" GUM_PTR_CONST ", uint64(2));"
      "p.writeU8(0x12);"
      "send('p', p.readByteArray(2));"
      "send('buf', " GUM_PTR_CONST ".readByteArray(2));",
      buf, buf);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"p\"", "12 37");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"buf\"", "13 37");
}

TESTCASE (memory_can_be_protected)
{
  gpointer buf;
  gboolean exception_on_read, exception_on_write;

  buf = gum_alloc_n_pages (1, GUM_PAGE_RW);

  COMPILE_AND_LOAD_SCRIPT (
      "send(Memory.protect(" GUM_PTR_CONST ", 1, 'r--'));",
      buf, gum_query_page_size ());
  EXPECT_SEND_MESSAGE_WITH ("true");

  if (gum_process_is_debugger_attached ())
  {
    g_print ("<only partially tested, debugger is attached> ");

    gum_free_pages (buf);

    return;
  }

  /* avoid overlapping signal handlers */
  UNLOAD_SCRIPT ();

  gum_try_read_and_write_at (buf, 0, &exception_on_read, &exception_on_write);
  g_assert_false (exception_on_read);
  g_assert_true (exception_on_write);

  COMPILE_AND_LOAD_SCRIPT (
      "send(Memory.protect(" GUM_PTR_CONST ", uint64(1), '---'));",
      buf, gum_query_page_size ());
  EXPECT_SEND_MESSAGE_WITH ("true");

  /* avoid overlapping signal handlers */
  UNLOAD_SCRIPT ();

  gum_try_read_and_write_at (buf, 0, &exception_on_read, &exception_on_write);
  g_assert_true (exception_on_read);
  g_assert_true (exception_on_write);

  gum_free_pages (buf);
}

TESTCASE (memory_protection_can_be_queried)
{
  gpointer buf;

  buf = gum_alloc_n_pages (1, GUM_PAGE_RW);

  COMPILE_AND_LOAD_SCRIPT (
      "const x = " GUM_PTR_CONST ";"
      "send(Memory.queryProtection(x) === 'rw-');"
      "Memory.protect(x, 1, 'r--');"
      "send(Memory.queryProtection(x) === 'r--');"
      "Memory.protect(x, 1, 'r-x');"
      "send(Memory.queryProtection(x) === 'r-x');"
      "Memory.protect(x, 1, 'rw-');"
      "send(Memory.queryProtection(x) === 'rw-');",
      buf);

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");

  gum_free_pages (buf);
}

TESTCASE (code_can_be_patched)
{
  guint8 * code;

  code = gum_alloc_n_pages (1, GUM_PAGE_RW);
  code[7] = 0xc3;
  gum_mprotect (code, gum_query_page_size (), GUM_PAGE_RX);

  COMPILE_AND_LOAD_SCRIPT ("Memory.patchCode(" GUM_PTR_CONST ", 1, ptr => {"
          "ptr.writeU8(0x90);"
      "});", code + 7);
  g_assert_cmphex (code[7], ==, 0x90);

  gum_free_pages (code);
}

TESTCASE (s8_can_be_read)
{
  gint8 val = -42;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readS8());", &val);
  EXPECT_SEND_MESSAGE_WITH ("-42");
}

TESTCASE (s8_can_be_written)
{
  gint8 val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeS8(-42);", &val);
  g_assert_cmpint (val, ==, -42);
}

TESTCASE (u8_can_be_read)
{
  guint8 val = 42;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readU8());", &val);
  EXPECT_SEND_MESSAGE_WITH ("42");
}

TESTCASE (u8_can_be_written)
{
  guint8 val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeU8(42);", &val);
  g_assert_cmpint (val, ==, 42);
}

TESTCASE (s16_can_be_read)
{
  gint16 val = -12123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readS16());", &val);
  EXPECT_SEND_MESSAGE_WITH ("-12123");
}

TESTCASE (s16_can_be_written)
{
  gint16 val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeS16(-12123);", &val);
  g_assert_cmpint (val, ==, -12123);
}

TESTCASE (u16_can_be_read)
{
  guint16 val = 12123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readU16());", &val);
  EXPECT_SEND_MESSAGE_WITH ("12123");
}

TESTCASE (u16_can_be_written)
{
  guint16 val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeU16(12123);", &val);
  g_assert_cmpint (val, ==, 12123);
}

TESTCASE (s32_can_be_read)
{
  gint32 val = -120123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readS32());", &val);
  EXPECT_SEND_MESSAGE_WITH ("-120123");
}

TESTCASE (s32_can_be_written)
{
  gint32 val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeS32(-120123);", &val);
  g_assert_cmpint (val, ==, -120123);
}

TESTCASE (u32_can_be_read)
{
  guint32 val = 120123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readU32());", &val);
  EXPECT_SEND_MESSAGE_WITH ("120123");
}

TESTCASE (u32_can_be_written)
{
  guint32 val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeU32(120123);", &val);
  g_assert_cmpint (val, ==, 120123);
}

TESTCASE (s64_can_be_read)
{
  gint64 val = G_GINT64_CONSTANT (-1201239876783);
  COMPILE_AND_LOAD_SCRIPT (
      "const value = " GUM_PTR_CONST ".readS64();"
      "send(value instanceof Int64);"
      "send(value);",
      &val);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"-1201239876783\"");
}

TESTCASE (s64_can_be_written)
{
  gint64 val = 0;
  COMPILE_AND_LOAD_SCRIPT (
      GUM_PTR_CONST ".writeS64(int64('-1201239876783'));", &val);
  g_assert_cmpint (val, ==, G_GINT64_CONSTANT (-1201239876783));
}

TESTCASE (u64_can_be_read)
{
  guint64 val = G_GUINT64_CONSTANT (1201239876783);
  COMPILE_AND_LOAD_SCRIPT (
      "const value = " GUM_PTR_CONST ".readU64();"
      "send(value instanceof UInt64);"
      "send(value);",
      &val);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"1201239876783\"");
}

TESTCASE (u64_can_be_written)
{
  gint64 val = 0;
  COMPILE_AND_LOAD_SCRIPT (
      GUM_PTR_CONST ".writeU64(uint64('1201239876783'));", &val);
  g_assert_cmpint (val, ==, G_GUINT64_CONSTANT (1201239876783));
}

TESTCASE (short_can_be_read)
{
  short val = -12123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readShort());", &val);
  EXPECT_SEND_MESSAGE_WITH ("-12123");
}

TESTCASE (short_can_be_written)
{
  short val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeShort(-12123);", &val);
  g_assert_cmpint (val, ==, -12123);

  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeShort(int64(-1234));", &val);
  g_assert_cmpint (val, ==, -1234);
}

TESTCASE (ushort_can_be_read)
{
  unsigned short val = 12123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUShort());", &val);
  EXPECT_SEND_MESSAGE_WITH ("12123");
}

TESTCASE (ushort_can_be_written)
{
  unsigned short val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeUShort(12123);", &val);
  g_assert_cmpint (val, ==, 12123);

  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeUShort(uint64(1234));", &val);
  g_assert_cmpint (val, ==, 1234);
}

TESTCASE (int_can_be_read)
{
  int val = -120123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readInt());", &val);
  EXPECT_SEND_MESSAGE_WITH ("-120123");
}

TESTCASE (int_can_be_written)
{
  int val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeInt(-120123);", &val);
  g_assert_cmpint (val, ==, -120123);
}

TESTCASE (uint_can_be_read)
{
  unsigned int val = 120123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUInt());", &val);
  EXPECT_SEND_MESSAGE_WITH ("120123");
}

TESTCASE (uint_can_be_written)
{
  unsigned int val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeUInt(120123);", &val);
  g_assert_cmpint (val, ==, 120123);
}

TESTCASE (long_can_be_read)
{
  long val = -123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readLong());", &val);
  EXPECT_SEND_MESSAGE_WITH ("\"-123\"");
}

TESTCASE (long_can_be_written)
{
  long val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeLong(1350966097);", &val);
  g_assert_cmpint (val, ==, 1350966097);
}

TESTCASE (ulong_can_be_read)
{
  unsigned long val = 4294967295UL;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readULong());", &val);
  EXPECT_SEND_MESSAGE_WITH ("\"4294967295\"");
}

TESTCASE (ulong_can_be_written)
{
  unsigned long val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeULong(4294967295);", &val);
  g_assert_cmpint (val, ==, 4294967295UL);
}

TESTCASE (float_can_be_read)
{
  float val = 123.456f;
  COMPILE_AND_LOAD_SCRIPT ("send(Math.abs(" GUM_PTR_CONST ".readFloat()"
      " - 123.456) < 0.00001);", &val);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (float_can_be_written)
{
  float val = 0.f;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeFloat(123.456);", &val);
  g_assert_cmpfloat (ABS (val - 123.456f), <, 0.00001f);
}

TESTCASE (double_can_be_read)
{
  double val = 123.456;
  COMPILE_AND_LOAD_SCRIPT ("send(Math.abs(" GUM_PTR_CONST ".readDouble()"
      " - 123.456) < 0.00001);", &val);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (double_can_be_written)
{
  double val = 0.0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeDouble(123.456);", &val);
  g_assert_cmpfloat (ABS (val - 123.456), <, 0.00001);
}

TESTCASE (byte_array_can_be_read)
{
  guint8 buf[3] = { 0x13, 0x37, 0x42 };
  COMPILE_AND_LOAD_SCRIPT (
      "const buffer = " GUM_PTR_CONST ".readByteArray(3);"
      "send('badger', buffer);"
      "send('badger', " GUM_PTR_CONST ".readByteArray(int64(3)));"
      "send('badger', " GUM_PTR_CONST ".readByteArray(uint64(3)));"
      "const emptyBuffer = " GUM_PTR_CONST ".readByteArray(0);"
      "send('snake', emptyBuffer);"
      "send(buffer instanceof ArrayBuffer);"
      "send(emptyBuffer instanceof ArrayBuffer);",
      buf, buf, buf, buf);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"badger\"", "13 37 42");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"badger\"", "13 37 42");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"badger\"", "13 37 42");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"snake\"", "");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (byte_array_can_be_written)
{
  guint8 val[4] = { 0x00, 0x00, 0x00, 0xff };
  const guint8 other[3] = { 0x01, 0x02, 0x03 };
  guint16 shorts[2] = { 0x1111, 0x2222 };

  COMPILE_AND_LOAD_SCRIPT (
      GUM_PTR_CONST ".writeByteArray([0x13, 0x37, 0x42]);",
      val);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (val[0], ==, 0x13);
  g_assert_cmpint (val[1], ==, 0x37);
  g_assert_cmpint (val[2], ==, 0x42);
  g_assert_cmpint (val[3], ==, 0xff);

  COMPILE_AND_LOAD_SCRIPT (
      "const other = " GUM_PTR_CONST ".readByteArray(3);"
      GUM_PTR_CONST ".writeByteArray(other);",
      other, val);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (val[0], ==, 0x01);
  g_assert_cmpint (val[1], ==, 0x02);
  g_assert_cmpint (val[2], ==, 0x03);
  g_assert_cmpint (val[3], ==, 0xff);

  COMPILE_AND_LOAD_SCRIPT (
      "const bytes = new Uint8Array(2);"
      "bytes[0] = 4;"
      "bytes[1] = 5;"
      GUM_PTR_CONST ".writeByteArray(bytes);",
      val);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (val[0], ==, 0x04);
  g_assert_cmpint (val[1], ==, 0x05);
  g_assert_cmpint (val[2], ==, 0x03);

  COMPILE_AND_LOAD_SCRIPT (
      "const shorts = new Uint16Array(1);"
      "shorts[0] = 0x4242;"
      GUM_PTR_CONST ".writeByteArray(shorts);",
      shorts);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (shorts[0], ==, 0x4242);
  g_assert_cmpint (shorts[1], ==, 0x2222);
}

TESTCASE (c_string_can_be_read)
{
  const gchar * str = "Hello";
  const gchar * uni = "Bjøærheimsbygd";

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readCString());",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Hello\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readCString(3));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Hel\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readCString(0));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readCString(-1));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Hello\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readCString(int64(-1)));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Hello\"");

  COMPILE_AND_LOAD_SCRIPT ("send(ptr('0').readCString());", str);
  EXPECT_SEND_MESSAGE_WITH ("null");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readCString(4));", uni);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjø\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readCString(3));", uni);
  EXPECT_SEND_MESSAGE_WITH ("\"Bj\357\277\275\"");
}

TESTCASE (utf8_string_can_be_read)
{
  const gchar * str = "Bjøærheimsbygd";

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf8String());", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjøærheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf8String(4));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjø\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf8String(0));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf8String(-1));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjøærheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf8String(int64(-1)));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjøærheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(ptr('0').readUtf8String());", str);
  EXPECT_SEND_MESSAGE_WITH ("null");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf8String(3));", str);
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: can't decode byte 0xc3 in position 2");
}

TESTCASE (utf8_string_can_be_written)
{
  gchar str[6];

  strcpy (str, "Hello");
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeUtf8String('Bye');", str);
  g_assert_cmpstr (str, ==, "Bye");
  g_assert_cmphex (str[4], ==, 'o');
  g_assert_cmphex (str[5], ==, '\0');
}

TESTCASE (utf8_string_can_be_allocated)
{
  COMPILE_AND_LOAD_SCRIPT ("send("
      "Memory.allocUtf8String('Bjørheimsbygd').readUtf8String()"
      ");");
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
}

TESTCASE (utf16_string_can_be_read)
{
  const gchar * str_utf8 = "Bjørheimsbygd";
  gunichar2 * str = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf16String());", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf16String(3));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjø\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf16String(0));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf16String(-1));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send("
      GUM_PTR_CONST ".readUtf16String(int64(-1))"
      ");",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
```