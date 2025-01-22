Response:
### 功能列举
1. **USDT探针跟踪**：通过用户态静态跟踪点（USDT）监控特定用户态程序的函数调用。
2. **输入过滤**：使用自定义字符串（`FILTER_STRING`）过滤操作请求。
3. **操作生命周期记录**：记录操作ID、输入字符串及开始时间戳，用于后续延迟分析。
4. **哈希表存储**：通过`BPF_HASH`暂存操作启动数据，等待后续完成事件关联。

---

### 执行顺序（分10步）
1. **用户态程序触发USDT探针**：当用户态程序执行到预定义的USDT探针点时触发。
2. **内核调用`trace_operation_start`**：eBPF程序通过USDT探针绑定此函数。
3. **读取输入参数**：通过`bpf_usdt_readarg_p`读取用户态程序的第2个参数（输入字符串）。
4. **应用过滤逻辑**：调用`filter`函数检查输入字符串是否匹配`FILTER_STRING`。
5. **过滤失败则退出**：若不匹配，直接结束处理。
6. **读取操作ID**：通过`bpf_usdt_readarg`读取用户态程序的第1个参数（操作ID）。
7. **记录时间戳**：调用`bpf_ktime_get_ns`获取当前纳秒级时间戳。
8. **存储到哈希表**：将操作ID、输入字符串和开始时间存入`start_hash`。
9. **用户态程序继续执行**：探针处理完成后，用户态程序继续运行。
10. **后续处理**：可能通过另一个USDT探针读取完成时间，结合哈希表计算延迟。

---

### Hook点与关键信息
| **Hook点类型** | **函数名**          | **读取的有效信息**                  | **信息含义**                      |
|----------------|--------------------|-----------------------------------|---------------------------------|
| USDT探针       | `trace_operation_start` | 用户态程序的第1个参数（`operation_id`） | 操作唯一标识符，用于关联生命周期事件。        |
|                |                    | 用户态程序的第2个参数（`input`）         | 操作输入字符串（如文件路径、请求参数等）。      |
|                |                    | `bpf_ktime_get_ns()`返回值       | 操作开始时间戳，用于计算延迟。             |

---

### 假设输入与输出
#### 输入示例
- **用户态程序调用**：触发探针时传入参数 `operation_id=123`, `input="FILTER_STRING/data/test.txt"`。
- **过滤逻辑**：`filter_string`被Python代码替换为`"FILTER_STRING"`。

#### 输出结果
- **哈希表条目**：`{operation_id=123, input="FILTER_STRING/data/test.txt", start=1620000000000}`。
- **过滤失败条目**：若输入为`"OTHER_STRING"`，则无哈希表更新。

---

### 常见使用错误
1. **USDT探针未启用**：
   - **错误现象**：`trace_operation_start`未被触发。
   - **解决方法**：确保用户态程序编译时启用USDT（如GCC `-g`选项），并通过`readelf -n`验证探针存在。

2. **字符串未正确替换**：
   - **错误现象**：`FILTER_STRING`未被Python代码替换，导致过滤失效。
   - **示例**：若Python脚本未替换`FILTER_STATEMENT`，过滤逻辑可能被跳过。

3. **指针解引用错误**：
   - **错误现象**：用户态传递的`input`为`NULL`，触发`filter`函数空指针检查。
   - **调试线索**：检查用户态程序传递参数的逻辑。

---

### Syscall到达此处的调试线索
1. **用户态程序调用路径**：
   - 用户代码调用库函数（如`libexample.so`中的`perform_operation()`）。
   - 库函数内插入USDT探针点（如`DTRACE_PROBE2(example, operation_start, id, input)`）。

2. **内核态触发流程**：
   - 用户态触发USDT探针时，内核通过`perf_event_open`将eBPF程序挂载到探针点。
   - 探针触发时，调用`trace_operation_start`，通过`pt_regs`访问用户态参数。

3. **调试验证步骤**：
   - 使用`bpftool prog list`确认eBPF程序已加载。
   - 通过`strace -e perf_event_open`跟踪探针绑定过程。
   - 在用户态程序中使用`bcc`的`trace.py`验证探针触发情况。
Prompt: 
```
这是目录为bcc/examples/usdt_sample/scripts/bpf_text_shared.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
#include <linux/blkdev.h>
#include <uapi/linux/ptrace.h>

/**
 * @brief Helper method to filter based on the specified inputString.
 * @param inputString The operation input string to check against the filter.
 * @return True if the specified inputString starts with the hard-coded filter string; otherwise, false.
 */
static inline bool filter(char const* inputString)
{
    static const char* null_ptr = 0x0;
    static const char null_terminator = '\0';

    static const char filter_string[] = "FILTER_STRING"; ///< The filter string is replaced by python code.
    if (null_ptr == inputString) {
        return false;
    }

    // Compare until (not including) the null-terminator for filter_string
    for (int i = 0; i < sizeof(filter_string) - 1; ++i) {
        char c1 = *inputString++;
        if (null_terminator == c1) {
            return false;  // If the null-terminator for inputString was reached, it can not be equal to filter_string.
        }

        char c2 = filter_string[i];
        if (c1 != c2) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Contains the operation start data to trace.
 */
struct start_data_t
{
    u64 operation_id; ///< The id of the operation.
    char input[64];   ///< The input string of the request.
    u64 start;        ///< Timestamp of the start operation (start timestamp).
};

/**
 * @brief Contains the operation start data.
 * key: the operation id.
 * value: The operation start latency data.
 */
BPF_HASH(start_hash, u64, struct start_data_t);

/**
 * @brief Reads the operation request arguments and stores the start data in the hash.
 * @param ctx The BPF context.
 */
int trace_operation_start(struct pt_regs* ctx)
{
    struct start_data_t start_data = {};
    bpf_usdt_readarg_p(2, ctx, &start_data.input, sizeof(start_data.input));

    FILTER_STATEMENT ///< Replaced by python code.

    bpf_usdt_readarg(1, ctx, &start_data.operation_id);

    start_data.start = bpf_ktime_get_ns();
    start_hash.update(&start_data.operation_id, &start_data);
    return 0;
}

"""

```