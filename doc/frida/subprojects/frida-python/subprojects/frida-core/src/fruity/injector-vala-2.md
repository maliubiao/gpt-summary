Response:
### 功能归纳

`injector.vala` 文件是 Frida 工具中用于动态注入的核心模块之一，主要负责在目标进程中注入代码并执行。以下是该文件的主要功能归纳：

1. **符号解析与查询**：
   - 通过 `SymbolQueryBuilder` 和 `SymbolQuery` 类，构建符号查询请求，支持按模块和符号名称进行查询。
   - `SymbolSet` 类用于存储和管理符号的地址信息，支持通过模块名和符号名查找符号地址。

2. **线程与内存管理**：
   - `ThreadedItemsBuilder` 和 `ThreadedItems` 类用于管理线程相关的符号引用和内存区域基址。
   - `ChainedFixupsBuilder` 和 `ChainedFixups` 类用于管理链式修复点（Chained Fixups），支持在注入过程中修复地址引用。

3. **远程函数调用**：
   - `invoke_remote_function` 方法用于在目标进程中调用远程函数。它通过 LLDB 调试器控制目标进程的寄存器状态，执行函数调用，并处理可能的异常。
   - 支持传递多个参数，并可以通过 `ExceptionHandler` 接口处理异常。

4. **异常处理与调试信息输出**：
   - `summarize_exception` 方法用于生成异常的详细摘要信息，包括调用栈和符号化地址。
   - `symbolicate_address` 方法用于将地址符号化为模块名和偏移量，便于调试。

5. **字符串与缓冲区管理**：
   - `StringVectorBuilder` 类用于构建字符串向量，支持在缓冲区中动态添加字符串，并生成指向这些字符串的指针数组。

6. **调试器集成**：
   - 通过 LLDB 调试器接口，控制目标进程的执行状态，读取和写入寄存器，生成调用栈等。

### 二进制底层与 Linux 内核相关

- **寄存器操作**：`invoke_remote_function` 方法通过 LLDB 调试器直接操作目标进程的寄存器（如 `pc`, `sp`, `lr`, `fp` 等），这些操作涉及到底层的 CPU 架构（如 ARM64）。
- **内存管理**：`ThreadedItemsBuilder` 和 `ThreadedItems` 类涉及到内存区域的基址管理，这些操作与操作系统的内存管理机制密切相关。
- **符号解析**：`symbolicate_address` 方法通过解析模块的加载地址和符号表，将地址符号化为模块名和偏移量，这涉及到 ELF 文件格式和动态链接库的加载机制。

### LLDB 调试示例

假设我们想要复现 `invoke_remote_function` 的功能，可以使用 LLDB 的 Python 脚本来模拟远程函数调用。以下是一个示例脚本：

```python
import lldb

def invoke_remote_function(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()

    # 设置寄存器
    thread.SetRegister("pc", 0x1000)  # 假设函数地址为 0x1000
    thread.SetRegister("lr", 1337)    # 设置返回地址
    thread.SetRegister("sp", 0x7fff0000)  # 设置栈指针
    thread.SetRegister("fp", 0)       # 设置帧指针

    # 设置参数
    thread.SetRegister("arg1", 0x1234)  # 设置第一个参数
    thread.SetRegister("arg2", 0x5678)  # 设置第二个参数

    # 继续执行直到返回
    process.Continue()

    # 读取返回值
    return_value = thread.GetRegister("x0").GetValueAsUnsigned()
    print(f"Return value: {return_value}")

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldb_script.invoke_remote_function invoke_remote')
```

### 假设输入与输出

- **输入**：假设我们要调用一个远程函数 `my_function`，地址为 `0x1000`，传递两个参数 `0x1234` 和 `0x5678`。
- **输出**：函数执行后，返回值存储在 `x0` 寄存器中，假设返回值为 `0xabcd`。

### 用户常见错误

1. **寄存器设置错误**：用户在设置寄存器时可能会错误地设置 `pc` 或 `sp`，导致程序崩溃或无法正确执行。
   - **示例**：将 `pc` 设置为无效地址，导致程序跳转到错误的位置。

2. **参数传递错误**：用户在传递参数时可能会错误地设置 `arg1`, `arg2` 等寄存器，导致函数接收到错误的参数。
   - **示例**：将 `arg1` 设置为 `0x0`，导致函数接收到空指针。

3. **异常处理不当**：如果远程函数抛出异常，用户可能没有正确处理异常，导致调试器无法继续执行。
   - **示例**：未实现 `ExceptionHandler` 接口，导致异常未被捕获，程序崩溃。

### 用户操作步骤

1. **启动调试器**：用户启动 LLDB 并附加到目标进程。
2. **设置断点**：用户在目标函数 `my_function` 的入口处设置断点。
3. **调用远程函数**：用户使用 `invoke_remote_function` 方法调用远程函数，传递参数并执行。
4. **处理异常**：如果函数抛出异常，用户通过 `ExceptionHandler` 接口处理异常。
5. **读取返回值**：函数执行完毕后，用户读取 `x0` 寄存器中的返回值。

### 调试线索

- **寄存器状态**：通过查看 `pc`, `sp`, `lr`, `fp` 等寄存器的状态，可以判断程序是否正常执行。
- **调用栈**：通过生成调用栈，可以定位函数调用过程中的问题。
- **符号化地址**：通过符号化地址，可以快速定位问题所在的模块和偏移量。

### 总结

`injector.vala` 文件实现了 Frida 工具中的核心注入功能，涉及到符号解析、远程函数调用、异常处理等复杂操作。通过 LLDB 调试器，用户可以模拟这些功能，并在目标进程中执行动态注入。
Prompt: 
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/fruity/injector.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第3部分，共3部分，请归纳一下它的功能

"""
, 0x41,
			0x14, 0x00, 0x70, 0x1f, 0x20, 0x03, 0xd5, 0x90, 0x00, 0x00, 0x94, 0x60, 0x01, 0x00, 0x34, 0x99, 0x0f, 0x40, 0xf9,
			0x04, 0x00, 0x00, 0x14, 0xf6, 0x03, 0x1c, 0xaa, 0x02, 0x00, 0x00, 0x14, 0xfb, 0x03, 0x1c, 0xaa, 0x88, 0x07, 0x40,
			0xb9, 0x9c, 0x03, 0x08, 0x8b, 0x5a, 0x07, 0x00, 0x51, 0x7a, 0xfd, 0xff, 0x35, 0x0b, 0x00, 0x00, 0x14, 0xe0, 0x03,
			0x17, 0xaa, 0xa1, 0x12, 0x00, 0x50, 0x1f, 0x20, 0x03, 0xd5, 0x81, 0x00, 0x00, 0x94, 0xe0, 0xfe, 0xff, 0x34, 0x88,
			0x0f, 0x40, 0xf9, 0x89, 0x17, 0x40, 0xf9, 0x08, 0x01, 0x09, 0xcb, 0xe8, 0x07, 0x00, 0xf9, 0xf2, 0xff, 0xff, 0x17,
			0x96, 0x00, 0x00, 0xb4, 0xc8, 0xa2, 0x00, 0x91, 0xf7, 0x03, 0x40, 0xf9, 0x04, 0x00, 0x00, 0x14, 0xf7, 0x03, 0x40,
			0xf9, 0xbb, 0x05, 0x00, 0xb4, 0x68, 0x23, 0x00, 0x91, 0xe9, 0x02, 0x19, 0xcb, 0xea, 0x07, 0x40, 0xf9, 0x49, 0x01,
			0x09, 0x8b, 0x08, 0x01, 0x40, 0xb9, 0x35, 0x01, 0x08, 0x8b, 0x61, 0x0f, 0x00, 0x10, 0x1f, 0x20, 0x03, 0xd5, 0xe0,
			0x03, 0x15, 0xaa, 0x31, 0x00, 0x00, 0x94, 0xf6, 0x02, 0x00, 0x8b, 0x01, 0x0f, 0x00, 0x10, 0x1f, 0x20, 0x03, 0xd5,
			0xe0, 0x03, 0x15, 0xaa, 0x2c, 0x00, 0x00, 0x94, 0xf7, 0x02, 0x00, 0x8b, 0x80, 0x02, 0x40, 0xf9, 0x60, 0x02, 0x00,
			0xb4, 0x21, 0x01, 0x80, 0x52, 0xc0, 0x02, 0x3f, 0xd6, 0x40, 0x01, 0x00, 0xb4, 0xf5, 0x03, 0x00, 0xaa, 0x94, 0x42,
			0x00, 0x91, 0x81, 0x82, 0x5f, 0xf8, 0x01, 0xff, 0xff, 0xb4, 0xe0, 0x03, 0x15, 0xaa, 0xe0, 0x02, 0x3f, 0xd6, 0x60,
			0x86, 0x00, 0xf8, 0x94, 0x22, 0x00, 0x91, 0xfa, 0xff, 0xff, 0x17, 0x94, 0x42, 0x00, 0x91, 0x88, 0x82, 0x5f, 0xf8,
			0x08, 0xfe, 0xff, 0xb4, 0x7f, 0x86, 0x00, 0xf8, 0x94, 0x22, 0x00, 0x91, 0xfc, 0xff, 0xff, 0x17, 0xfd, 0x7b, 0x46,
			0xa9, 0xf4, 0x4f, 0x45, 0xa9, 0xf6, 0x57, 0x44, 0xa9, 0xf8, 0x5f, 0x43, 0xa9, 0xfa, 0x67, 0x42, 0xa9, 0xfc, 0x6f,
			0x41, 0xa9, 0xff, 0xc3, 0x01, 0x91, 0xc0, 0x03, 0x5f, 0xd6, 0x15, 0x00, 0x80, 0xd2, 0xd9, 0xff, 0xff, 0x17, 0xe8,
			0x03, 0x00, 0xaa, 0x0a, 0x00, 0x80, 0xd2, 0x00, 0x00, 0x80, 0xd2, 0x09, 0x01, 0x40, 0xf9, 0x2b, 0x15, 0x40, 0x38,
			0x6c, 0x19, 0x40, 0x92, 0x8c, 0x21, 0xca, 0x9a, 0x80, 0x01, 0x00, 0xaa, 0x4a, 0x1d, 0x00, 0x91, 0x6b, 0xff, 0x3f,
			0x37, 0x09, 0x01, 0x00, 0xf9, 0xc0, 0x03, 0x5f, 0xd6, 0xff, 0x43, 0x01, 0xd1, 0xf8, 0x5f, 0x01, 0xa9, 0xf6, 0x57,
			0x02, 0xa9, 0xf4, 0x4f, 0x03, 0xa9, 0xfd, 0x7b, 0x04, 0xa9, 0xfd, 0x03, 0x01, 0x91, 0xf4, 0x03, 0x01, 0xaa, 0xf3,
			0x03, 0x00, 0xaa, 0xe8, 0x03, 0x00, 0xaa, 0xe8, 0x07, 0x00, 0xf9, 0xc8, 0x04, 0x00, 0xb4, 0x3a, 0x00, 0x00, 0x94,
			0x60, 0x00, 0x00, 0xb4, 0x88, 0x02, 0x40, 0x39, 0x88, 0x04, 0x00, 0x34, 0x15, 0x00, 0x80, 0x52, 0xe8, 0x07, 0x40,
			0xf9, 0x08, 0x01, 0x00, 0x8b, 0x16, 0x15, 0x40, 0x38, 0xe8, 0x07, 0x00, 0xf9, 0xdf, 0x02, 0x35, 0x6b, 0xc0, 0x02,
			0x00, 0x54, 0xe8, 0x07, 0x40, 0xf9, 0x08, 0x05, 0x00, 0x91, 0x38, 0x00, 0x80, 0x52, 0xf7, 0x03, 0x14, 0xaa, 0x09,
			0xf1, 0x5f, 0x38, 0x49, 0x01, 0x00, 0x34, 0xb8, 0x00, 0x00, 0x36, 0xea, 0x16, 0xc0, 0x38, 0x3f, 0x01, 0x0a, 0x6b,
			0xf8, 0x17, 0x9f, 0x1a, 0x02, 0x00, 0x00, 0x14, 0x18, 0x00, 0x80, 0x52, 0xe8, 0x07, 0x00, 0xf9, 0x08, 0x05, 0x00,
			0x91, 0xf6, 0xff, 0xff, 0x17, 0xe8, 0x07, 0x00, 0xf9, 0x1f, 0x00, 0x00, 0x94, 0xb5, 0x06, 0x00, 0x11, 0x98, 0xfd,
			0x07, 0x36, 0xf4, 0x03, 0x17, 0xaa, 0x02, 0x00, 0x00, 0x14, 0x00, 0x00, 0x80, 0xd2, 0x68, 0x02, 0x00, 0x8b, 0x1f,
			0x00, 0x00, 0xf1, 0xe8, 0x03, 0x88, 0x9a, 0xda, 0xff, 0xff, 0x17, 0x00, 0x00, 0x80, 0xd2, 0x03, 0x00, 0x00, 0x14,
			0x13, 0x00, 0x00, 0x94, 0x12, 0x00, 0x00, 0x94, 0xfd, 0x7b, 0x44, 0xa9, 0xf4, 0x4f, 0x43, 0xa9, 0xf6, 0x57, 0x42,
			0xa9, 0xf8, 0x5f, 0x41, 0xa9, 0xff, 0x43, 0x01, 0x91, 0xc0, 0x03, 0x5f, 0xd6, 0x08, 0x00, 0x40, 0x39, 0x29, 0x00,
			0x40, 0x39, 0x1f, 0x01, 0x09, 0x6b, 0xc1, 0x00, 0x00, 0x54, 0x00, 0x04, 0x00, 0x91, 0x21, 0x04, 0x00, 0x91, 0x48,
			0xff, 0xff, 0x35, 0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6, 0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
			0xe0, 0x23, 0x00, 0x91, 0xae, 0xff, 0xff, 0x17, 0x5f, 0x64, 0x6c, 0x6f, 0x70, 0x65, 0x6e, 0x00, 0x5f, 0x64, 0x6c,
			0x73, 0x79, 0x6d, 0x00, 0x5f, 0x5f, 0x54, 0x45, 0x58, 0x54, 0x00, 0x5f, 0x5f, 0x4c, 0x49, 0x4e, 0x4b, 0x45, 0x44,
			0x49, 0x54, 0x00, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x6c, 0x69, 0x62, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2f,
			0x6c, 0x69, 0x62, 0x64, 0x79, 0x6c, 0x64, 0x2e, 0x64, 0x79, 0x6c, 0x69, 0x62, 0x00
		};

		private string demangle (string symbol_name) {
			return (symbol_name[0] == '_')
				? symbol_name.substring (1)
				: symbol_name;
		}

		private class SymbolQueryBuilder {
			private Gee.Map<string, Gee.HashSet<string>> symbols = new Gee.HashMap<string, Gee.HashSet<string>> ();

			public unowned SymbolQueryBuilder add (string module_name, string symbol_name) {
				var group = symbols[module_name];
				if (group == null) {
					group = new Gee.HashSet<string> ();
					symbols[module_name] = group;
				}

				group.add (symbol_name);

				return this;
			}

			public SymbolQuery build () {
				var query = new SymbolQuery ();

				var groups = query.groups;
				foreach (var module_entry in symbols.entries) {
					unowned string module_name = module_entry.key;

					var group = new SymbolQueryGroup (module_name);
					groups.add (group);

					var names = group.symbol_names;
					foreach (var symbol_name in module_entry.value)
						names.add (symbol_name);
				}

				return query;
			}
		}

		private class SymbolQuery {
			public Gee.ArrayList<SymbolQueryGroup> groups {
				get;
				private set;
			}

			public SymbolQuery () {
				this.groups = new Gee.ArrayList<SymbolQueryGroup> ();
			}
		}

		private class SymbolQueryGroup {
			public string module_name {
				get;
				private set;
			}

			public Gee.ArrayList<string> symbol_names {
				get;
				private set;
			}

			public SymbolQueryGroup (string module_name) {
				this.module_name = module_name;
				this.symbol_names = new Gee.ArrayList<string> ();
			}
		}

		private class SymbolSet {
			private Gee.Map<string, Gee.Map<string, uint64?>> symbols =
				new Gee.HashMap<string, Gee.Map<string, uint64?>> ();

			public SymbolSet (Gee.Map<string, Gee.Map<string, uint64?>> symbols) {
				this.symbols = symbols;
			}

			public uint64 get (string module_name, string symbol_name) throws Error {
				uint64 address;
				if (!lookup (module_name, symbol_name, out address))
					throw new Error.UNSUPPORTED ("Symbol not found: %s", symbol_name);
				return address;
			}

			public bool lookup (string module_name, string symbol_name, out uint64 address) {
				address = 0;

				var group = symbols[module_name];
				if (group == null)
					return false;

				uint64? val = group[symbol_name];
				if (val == null)
					return false;

				address = val;
				return true;
			}
		}

		private class ThreadedItemsBuilder {
			private Gee.ArrayList<SymbolReference> symbol_refs = new Gee.ArrayList<SymbolReference> ();
			private Gee.ArrayList<uint64?> region_bases = new Gee.ArrayList<uint64?> ();

			public bool is_empty {
				get {
					return region_bases.is_empty;
				}
			}

			public unowned ThreadedItemsBuilder add_symbol (string module_name, string symbol_name) {
				symbol_refs.add (new SymbolReference (module_name, symbol_name));

				return this;
			}

			public unowned ThreadedItemsBuilder add_region (uint64 base_address) {
				region_bases.add (base_address);

				return this;
			}

			public ThreadedItems build (SymbolSet symbols) throws Error {
				var symbol_addrs = new Gee.ArrayList<uint64?> ();

				var result = new ThreadedItems (symbol_addrs, region_bases);

				foreach (var r in symbol_refs)
					symbol_addrs.add (symbols.get (r.module_name, r.symbol_name));

				return result;
			}

			private class SymbolReference {
				public string module_name;
				public string symbol_name;

				public SymbolReference (string module_name, string symbol_name) {
					this.module_name = module_name;
					this.symbol_name = symbol_name;
				}
			}
		}

		private class ThreadedItems {
			public bool is_empty {
				get {
					return region_bases.is_empty;
				}
			}

			public Gee.ArrayList<uint64?> symbol_addrs {
				get;
				private set;
			}

			public Gee.ArrayList<uint64?> region_bases {
				get;
				private set;
			}

			public ThreadedItems (Gee.ArrayList<uint64?> symbol_addrs, Gee.ArrayList<uint64?> region_bases) {
				this.symbol_addrs = symbol_addrs;
				this.region_bases = region_bases;
			}
		}

		private class ChainedFixupsBuilder {
			private Gee.ArrayList<uint64?> locations = new Gee.ArrayList<uint64?> ();

			public unowned ChainedFixupsBuilder add_location (Gum.Address vm_address) {
				locations.add (vm_address);
				return this;
			}

			public ChainedFixups build () throws Error {
				return new ChainedFixups (locations);
			}
		}

		private class ChainedFixups {
			public Gee.ArrayList<uint64?> locations {
				get;
				private set;
			}

			public ChainedFixups (Gee.ArrayList<uint64?> locations) {
				this.locations = locations;
			}
		}

		private class StringVectorBuilder {
			private BufferBuilder buffer_builder;
			private Gee.ArrayList<int> vector = new Gee.ArrayList<int> ();
			private size_t start_offset;

			public uint length {
				get {
					return vector.size;
				}
			}

			public StringVectorBuilder (BufferBuilder buffer_builder) {
				this.buffer_builder = buffer_builder;
			}

			public unowned StringVectorBuilder append_string (string val) {
				var offset = buffer_builder.offset;
				buffer_builder.append_string (val);
				vector.add ((int) offset);
				return this;
			}

			public unowned StringVectorBuilder append_terminator () {
				vector.add (-1);
				return this;
			}

			public size_t append_placeholder () {
				start_offset = buffer_builder.offset;

				buffer_builder.skip (vector.size * buffer_builder.pointer_size);

				return start_offset;
			}

			public void build (uint64 address) {
				var vector_offset = start_offset;
				var pointer_size = buffer_builder.pointer_size;

				foreach (int string_offset in vector) {
					uint64 val = (string_offset != -1) ? address + string_offset : 0;
					buffer_builder.write_pointer (vector_offset, val);

					vector_offset += pointer_size;
				}
			}
		}

		private async uint64 invoke_remote_function (uint64 impl, uint64[] args, ExceptionHandler? exception_handler,
				Cancellable? cancellable) throws GLib.Error {
			if (stack_bounds == null) {
				uint64 old_sp = yield main_thread.read_register ("sp", cancellable);
				uint64 our_sp = (old_sp - (old_sp % 16)) - 128;
				stack_bounds = LLDB.Thread.StackBounds (our_sp - (512 * 1024), our_sp);
			}

			yield main_thread.write_register ("pc", impl, cancellable);
			yield main_thread.write_register ("lr", 1337, cancellable);
			yield main_thread.write_register ("sp", stack_bounds.top, cancellable);
			yield main_thread.write_register ("fp", 0, cancellable);

			uint arg_id = 1;
			foreach (uint64 arg_val in args) {
				yield main_thread.write_register ("arg%u".printf (arg_id), arg_val, cancellable);
				arg_id++;
			}

			while (true) {
				var exception = (LLDB.Exception) yield lldb.continue_until_exception (cancellable);

				uint64 pc = exception.context["pc"];
				if (pc == 1337)
					break;

				if (exception_handler != null) {
					bool handled = yield exception_handler.try_handle_exception (exception, cancellable);
					if (handled)
						continue;
				}

				throw new Error.UNSUPPORTED ("Invocation of 0x%" + uint64.FORMAT_MODIFIER + "x crashed at %s",
					impl, yield summarize_exception (exception, cancellable));
			}

			return yield main_thread.read_register ("x0", cancellable);
		}

		/*
		private async void dump_lldb_state (Cancellable? cancellable) throws GLib.Error {
			var exception = lldb.exception;
			if (exception != null) {
				var summary = yield summarize_exception (exception, cancellable);
				printerr ("\n# EXCEPTION IN THREAD 0x%x\n\n%s\n", exception.thread.id, summary);
			}

			var threads = new Gee.ArrayList<LLDB.Thread> ();
			yield lldb.enumerate_threads (t => {
				threads.add (t);
				return true;
			}, cancellable);

			var cached_modules = new Gee.ArrayList<LLDB.Module> ();

			printerr ("\nMAIN THREAD: 0x%x\n", main_thread.id);
			printerr ("THREAD COUNT: %u\n", threads.size);

			foreach (var thread in threads) {
				printerr ("\nTHREAD 0x%x:\n", thread.id);

				var pc = yield thread.read_register ("pc", cancellable);
				printerr ("   0x%016" + uint64.FORMAT_MODIFIER + "x\t%s\n",
					pc,
					yield symbolicate_address (pc, cached_modules, cancellable));

				LLDB.Thread.StackBounds? bounds = null;
				if (thread.id == main_thread.id && stack_bounds != null)
					bounds = stack_bounds;

				var frames = yield thread.generate_backtrace (bounds, cancellable);
				foreach (var frame in frames) {
					if (frame.address == 1337)
						break;

					printerr ("   0x%016" + uint64.FORMAT_MODIFIER + "x\t%s\n",
						frame.address,
						yield symbolicate_address (frame.address, cached_modules, cancellable));
				}
			}
		}
		*/

		private async string summarize_exception (LLDB.Exception exception, Cancellable? cancellable) throws GLib.Error {
			var summary = new StringBuilder.sized (256);

			var cached_modules = new Gee.ArrayList<LLDB.Module> ();

			var context = exception.context;
			uint64 pc = context["pc"];
			string pc_symbol = yield symbolicate_address (pc, cached_modules, cancellable);

			summary
				.append (pc_symbol)
				.append (": ")
				.append (exception.to_string ());

			LLDB.Thread.StackBounds? bounds = null;
			if (exception.thread.id == main_thread.id && stack_bounds != null)
				bounds = stack_bounds;

			summary.append_printf ("\n\nLOCATION:\n   0x%016" + uint64.FORMAT_MODIFIER + "x\t%s", pc, pc_symbol);

			var thread = (LLDB.Thread) exception.thread;
			var frames = yield thread.generate_backtrace (bounds, cancellable);
			foreach (var frame in frames) {
				if (frame.address == 1337)
					break;

				summary.append_printf ("\n   0x%016" + uint64.FORMAT_MODIFIER + "x\t%s",
					frame.address,
					yield symbolicate_address (frame.address, cached_modules, cancellable));
			}

			return summary.str;
		}

		private async string symbolicate_address (uint64 address, Gee.ArrayList<LLDB.Module> cached_modules,
				Cancellable? cancellable) throws GLib.Error {
			string? description = null;

			if (address >= module.base_address && address < module.base_address + module_size) {
				description = format_module_symbol (module.name, module.base_address, address);
			} else {
				if (cached_modules.is_empty) {
					yield lldb.enumerate_modules (m => {
						cached_modules.add (m);
						return true;
					}, cancellable);
				}

				foreach (var m in cached_modules) {
					var text_segment = m.segments.first_match (s => s.name == "__TEXT");
					if (text_segment != null &&
							address >= m.load_address &&
							address < m.load_address + text_segment.vmsize) {
						description = format_module_symbol (m.pathname, m.load_address, address);
						break;
					}
				}
			}

			if (description == null)
				description = ("0x%" + uint64.FORMAT_MODIFIER + "x").printf (address);

			return description;
		}

		private static string format_module_symbol (string module_name, uint64 module_base, uint64 module_symbol) {
			var tokens = module_name.split ("/");
			unowned string module_basename = tokens[tokens.length - 1];
			uint64 offset = module_symbol - module_base;

			return ("%s!0x%" + uint64.FORMAT_MODIFIER + "x").printf (module_basename, offset);
		}
	}

	private interface ExceptionHandler : Object {
		public abstract async bool try_handle_exception (LLDB.Exception exception, Cancellable? cancellable)
			throws GLib.Error;
	}
}

"""


```