Response:
### 功能归纳

该源代码文件是 Frida 动态插桩工具的一部分，主要功能是通过 GDB（GNU 调试器）与目标进程进行交互，实现内存读写、断点管理、线程控制等调试功能。以下是该文件的主要功能归纳：

1. **内存读写操作**：
   - 支持读取和写入目标进程的内存数据，包括浮点数、双精度浮点数、字节数组、C 字符串、UTF-8 字符串等。
   - 提供了 `on_gdb_read_float`、`on_gdb_write_float`、`on_gdb_read_double`、`on_gdb_write_double` 等函数，用于处理不同类型的数据读写。

2. **断点管理**：
   - 支持在目标进程中添加、启用、禁用和删除断点。
   - 提供了 `on_gdb_add_breakpoint`、`on_gdb_breakpoint_enable`、`on_gdb_breakpoint_disable`、`on_gdb_breakpoint_remove` 等函数，用于管理断点。

3. **线程控制**：
   - 支持对目标进程中的线程进行控制，包括单步执行、读取寄存器、写入寄存器等操作。
   - 提供了 `on_gdb_thread_step`、`on_gdb_thread_read_registers`、`on_gdb_thread_write_register` 等函数，用于控制线程。

4. **远程命令执行**：
   - 支持在目标进程中执行远程命令，并获取执行结果。
   - 提供了 `on_gdb_run_remote_command` 函数，用于执行远程命令。

5. **GDB 查询与执行**：
   - 支持向 GDB 发送查询请求并获取响应。
   - 提供了 `on_gdb_query`、`on_gdb_execute` 等函数，用于与 GDB 进行交互。

6. **数据类型解析与序列化**：
   - 提供了多种数据类型的解析与序列化函数，如 `parse_raw_float`、`unparse_raw_float`、`parse_raw_double`、`unparse_raw_double` 等，用于处理不同类型的数据。

7. **错误处理与异常抛出**：
   - 在操作失败时，会抛出 JavaScript 异常，并通过 `throw_js_error` 函数将错误信息传递给调用者。

### 二进制底层与 Linux 内核相关

- **内存读写**：通过 GDB 的 `read_byte_array` 和 `write_byte_array` 函数，直接与目标进程的内存进行交互。这些操作涉及到二进制数据的读取和写入，通常用于调试和分析底层内存布局。
- **寄存器操作**：通过 `read_registers` 和 `write_register` 函数，直接读取和修改目标进程的寄存器值。这在调试内核模块或驱动程序时非常有用，因为寄存器的状态直接反映了 CPU 的执行状态。
- **断点管理**：断点的添加、启用、禁用和删除操作涉及到修改目标进程的代码段，通常用于调试内核代码或用户态程序的关键路径。

### LLDB 指令或 LLDB Python 脚本示例

假设我们想要复现 `on_gdb_read_float` 的功能，即从目标进程的内存中读取一个浮点数。我们可以使用 LLDB 的 Python 脚本来实现类似的功能。

```python
import lldb

def read_float(process, address):
    # 读取 4 字节的浮点数
    error = lldb.SBError()
    data = process.ReadMemory(address, 4, error)
    if error.Success():
        # 将字节数据转换为浮点数
        import struct
        float_value = struct.unpack('f', data)[0]
        return float_value
    else:
        print(f"Failed to read memory: {error}")
        return None

# 示例用法
target = lldb.debugger.GetSelectedTarget()
process = target.GetProcess()
address = 0x1000  # 假设的内存地址
float_value = read_float(process, address)
if float_value is not None:
    print(f"Read float value: {float_value}")
```

### 假设输入与输出

- **输入**：假设我们有一个目标进程，其内存地址 `0x1000` 处存储了一个浮点数 `3.14`。
- **输出**：调用 `read_float` 函数后，输出应为 `3.14`。

### 用户常见错误

1. **内存地址错误**：
   - 用户可能会提供一个无效的内存地址，导致内存读取失败。例如，提供的地址超出了目标进程的地址空间。
   - **示例**：用户尝试读取 `0xFFFFFFFFFFFFFFFF` 处的内存，导致 `ReadMemory` 失败。

2. **数据类型不匹配**：
   - 用户可能会尝试读取一个非浮点数的内存区域，导致解析错误。例如，读取一个整数并将其解析为浮点数。
   - **示例**：用户尝试读取 `0x1000` 处的整数 `42`，并将其解析为浮点数，导致结果不正确。

3. **断点管理错误**：
   - 用户可能会尝试在一个无效的地址上添加断点，或者尝试启用一个已经被删除的断点。
   - **示例**：用户尝试在 `0x1000` 处添加断点，但该地址不在目标进程的代码段中，导致断点添加失败。

### 用户操作路径

1. **启动调试会话**：
   - 用户启动 Frida 并附加到目标进程。
   - 用户编写 JavaScript 脚本，调用 `on_gdb_read_float` 函数，传入目标内存地址。

2. **内存读取**：
   - Frida 通过 GDB 读取目标进程的内存数据。
   - 如果读取成功，Frida 将数据解析为浮点数并返回给用户。

3. **错误处理**：
   - 如果读取失败（例如，无效的内存地址），Frida 会抛出 JavaScript 异常，用户可以在脚本中捕获并处理该异常。

4. **断点管理**：
   - 用户调用 `on_gdb_add_breakpoint` 函数，传入断点类型、地址和大小。
   - Frida 通过 GDB 在目标进程中添加断点，并返回断点对象。
   - 用户可以通过断点对象启用、禁用或删除断点。

### 总结

该源代码文件实现了 Frida 与 GDB 的深度集成，提供了强大的调试功能，包括内存读写、断点管理、线程控制等。通过这些功能，用户可以深入分析目标进程的执行状态，调试底层代码，甚至修改内存和寄存器值。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/barebone/script.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
uickJS.Value on_gdb_read_float (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_read (ctx, this_val, argv, 4, script->parse_raw_float);
		}

		private static QuickJS.Value on_gdb_write_float (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_write (ctx, this_val, argv, script->unparse_raw_float);
		}

		private static QuickJS.Value on_gdb_read_double (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_read (ctx, this_val, argv, 8, script->parse_raw_double);
		}

		private static QuickJS.Value on_gdb_write_double (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_write (ctx, this_val, argv, script->unparse_raw_double);
		}

		private static QuickJS.Value on_gdb_read_byte_array (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			uint size;
			if (!script->unparse_uint (argv[1], out size))
				return QuickJS.Exception;

			return script->do_gdb_read (ctx, this_val, argv, size, script->parse_raw_byte_array);
		}

		private static QuickJS.Value on_gdb_write_byte_array (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_write (ctx, this_val, argv, script->unparse_raw_byte_array);
		}

		private static QuickJS.Value on_gdb_read_c_string (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			ByteArray? bytes = script->do_gdb_read_null_terminated_string (ctx, this_val, argv);
			if (bytes == null)
				return QuickJS.Exception;

			unowned string raw_str = (string) bytes.data;
			string str = raw_str.make_valid ();

			return ctx.make_string (str);
		}

		private static QuickJS.Value on_gdb_read_utf8_string (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			ByteArray? bytes = script->do_gdb_read_null_terminated_string (ctx, this_val, argv);
			if (bytes == null)
				return QuickJS.Exception;

			unowned string str = (string) bytes.data;
			char * end;
			if (!str.validate (-1, out end)) {
				script->throw_js_error ("can't decode byte 0x%02x in position %u".printf (
					*((uint8 *) end),
					(uint) (end - (char *) str)));
				return QuickJS.Exception;
			}

			return ctx.make_string (str);
		}

		private ByteArray? do_gdb_read_null_terminated_string (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			uint64 address;
			if (!unparse_uint64 (argv[0], out address))
				return null;

			uint limit = 0;
			if (!argv[1].is_undefined () && !unparse_uint (argv[1], out limit))
				return null;

			var result = new ByteArray ();

			bool reached_terminator = false;
			uint offset = 0;
			uint chunk_size = 16;
			uint page_size = 4096;
			do {
				uint64 chunk_start = address + offset;

				uint64 next_page_start = (address & ~((uint64) page_size - 1)) + page_size;
				uint distance_to_next_page = (uint) (next_page_start - chunk_start);
				uint n = uint.min (chunk_size, distance_to_next_page);

				Bytes? chunk = read_memory (chunk_start, n);
				if (chunk == null)
					return null;

				foreach (uint8 byte in chunk.get_data ()) {
					if (byte == 0 || (limit != 0 && result.len == limit)) {
						reached_terminator = true;
						break;
					}
					result.append ({ byte });
					offset++;
				}

				chunk_size = uint.min (chunk_size * 2, 1024);
			} while (!reached_terminator);

			result.append ({ 0 });
			result.len--;

			return result;
		}

		private static QuickJS.Value on_gdb_write_utf8_string (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_write (ctx, this_val, argv, script->unparse_raw_utf8_string);
		}

		private QuickJS.Value parse_raw_pointer (Buffer buffer) {
			return make_native_pointer (buffer.read_pointer (0));
		}

		private BufferBuilder? unparse_raw_pointer (QuickJS.Value val, BufferBuilder builder) {
			uint64 v;
			if (!unparse_uint64 (val, out v))
				return null;
			return builder.append_pointer (v);
		}

		private QuickJS.Value parse_raw_s8 (Buffer buffer) {
			return ctx.make_int32 (buffer.read_int8 (0));
		}

		private BufferBuilder? unparse_raw_s8 (QuickJS.Value val, BufferBuilder builder) {
			int8 v;
			if (!unparse_int8 (val, out v))
				return null;
			return builder.append_int8 (v);
		}

		private QuickJS.Value parse_raw_u8 (Buffer buffer) {
			return ctx.make_uint32 (buffer.read_uint8 (0));
		}

		private BufferBuilder? unparse_raw_u8 (QuickJS.Value val, BufferBuilder builder) {
			uint8 v;
			if (!unparse_uint8 (val, out v))
				return null;
			return builder.append_uint8 (v);
		}

		private QuickJS.Value parse_raw_s16 (Buffer buffer) {
			return ctx.make_int32 (buffer.read_int16 (0));
		}

		private BufferBuilder? unparse_raw_s16 (QuickJS.Value val, BufferBuilder builder) {
			int16 v;
			if (!unparse_int16 (val, out v))
				return null;
			return builder.append_int16 (v);
		}

		private QuickJS.Value parse_raw_u16 (Buffer buffer) {
			return ctx.make_uint32 (buffer.read_uint16 (0));
		}

		private BufferBuilder? unparse_raw_u16 (QuickJS.Value val, BufferBuilder builder) {
			uint16 v;
			if (!unparse_uint16 (val, out v))
				return null;
			return builder.append_uint16 (v);
		}

		private QuickJS.Value parse_raw_s32 (Buffer buffer) {
			return ctx.make_int32 (buffer.read_int32 (0));
		}

		private BufferBuilder? unparse_raw_s32 (QuickJS.Value val, BufferBuilder builder) {
			int32 v;
			if (!unparse_int32 (val, out v))
				return null;
			return builder.append_int32 (v);
		}

		private QuickJS.Value parse_raw_u32 (Buffer buffer) {
			return ctx.make_uint32 (buffer.read_uint32 (0));
		}

		private BufferBuilder? unparse_raw_u32 (QuickJS.Value val, BufferBuilder builder) {
			uint32 v;
			if (!unparse_uint32 (val, out v))
				return null;
			return builder.append_uint32 (v);
		}

		private QuickJS.Value parse_raw_s64 (Buffer buffer) {
			return make_int64 (buffer.read_int64 (0));
		}

		private BufferBuilder? unparse_raw_s64 (QuickJS.Value val, BufferBuilder builder) {
			int64 v;
			if (!unparse_int64 (val, out v))
				return null;
			return builder.append_int64 (v);
		}

		private QuickJS.Value parse_raw_u64 (Buffer buffer) {
			return make_uint64 (buffer.read_uint64 (0));
		}

		private BufferBuilder? unparse_raw_u64 (QuickJS.Value val, BufferBuilder builder) {
			uint64 v;
			if (!unparse_uint64 (val, out v))
				return null;
			return builder.append_uint64 (v);
		}

		private QuickJS.Value parse_raw_float (Buffer buffer) {
			return ctx.make_float64 (buffer.read_float (0));
		}

		private BufferBuilder? unparse_raw_float (QuickJS.Value val, BufferBuilder builder) {
			double d;
			if (!unparse_double (val, out d))
				return null;
			return builder.append_float ((float) d);
		}

		private QuickJS.Value parse_raw_double (Buffer buffer) {
			return ctx.make_float64 (buffer.read_double (0));
		}

		private BufferBuilder? unparse_raw_double (QuickJS.Value val, BufferBuilder builder) {
			double d;
			if (!unparse_double (val, out d))
				return null;
			return builder.append_double (d);
		}

		private QuickJS.Value parse_raw_byte_array (Buffer buffer) {
			return ctx.make_array_buffer (buffer.bytes.get_data ());
		}

		private BufferBuilder? unparse_raw_byte_array (QuickJS.Value val, BufferBuilder builder) {
			Bytes bytes;
			if (!unparse_bytes (val, out bytes))
				return null;
			return builder.append_bytes (bytes);
		}

		private BufferBuilder? unparse_raw_utf8_string (QuickJS.Value val, BufferBuilder builder) {
			string str;
			if (!unparse_string (val, out str))
				return null;
			return builder.append_string (str);
		}

		private QuickJS.Value do_gdb_read (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv, uint size,
				GdbReadResultParseFunc parse) {
			uint64 address;
			if (!unparse_uint64 (argv[0], out address))
				return QuickJS.Exception;

			Bytes? bytes = read_memory (address, size);
			if (bytes == null)
				return QuickJS.Exception;

			return parse (gdb.make_buffer (bytes));
		}

		private delegate QuickJS.Value GdbReadResultParseFunc (Buffer buffer);

		private QuickJS.Value do_gdb_write (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv,
				GdbWriteUnparseFunc unparse) {
			uint64 address;
			if (!unparse_uint64 (argv[0], out address))
				return QuickJS.Exception;

			BufferBuilder? builder = unparse (argv[1], gdb.make_buffer_builder ());
			if (builder == null)
				return QuickJS.Exception;
			Bytes bytes = builder.build ();

			if (!write_memory (address, bytes))
				return QuickJS.Exception;

			return QuickJS.Undefined;
		}

		private delegate BufferBuilder? GdbWriteUnparseFunc (QuickJS.Value val, BufferBuilder builder);

		private Bytes? read_memory (uint64 address, uint size) {
			var promise = new Promise<Bytes> ();
			do_read_memory.begin (address, size, promise);
			return process_events_until_ready<Bytes> (promise);
		}

		private async void do_read_memory (uint64 address, uint size, Promise<Bytes> promise) {
			try {
				Bytes bytes = yield gdb.read_byte_array (address, size, io_cancellable);

				promise.resolve (bytes);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private bool write_memory (uint64 address, Bytes bytes) {
			var promise = new Promise<GDB.Client> ();
			do_write_memory.begin (address, bytes, promise);
			return process_events_until_ready<GDB.Client> (promise) != null;
		}

		private async void do_write_memory (uint64 address, Bytes bytes, Promise<GDB.Client> promise) {
			try {
				yield gdb.write_byte_array (address, bytes, io_cancellable);

				promise.resolve (gdb);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private static QuickJS.Value on_gdb_add_breakpoint (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			GDB.Breakpoint.Kind kind;
			if (!script->unparse_enum<GDB.Breakpoint.Kind> (argv[0], out kind))
				return QuickJS.Exception;

			uint64 address;
			if (!script->unparse_uint64 (argv[1], out address))
				return QuickJS.Exception;

			uint size;
			if (!script->unparse_uint (argv[2], out size))
				return QuickJS.Exception;

			var promise = new Promise<GDB.Breakpoint> ();
			script->do_gdb_add_breakpoint.begin (kind, address, size, promise);

			GDB.Breakpoint? bp = script->process_events_until_ready (promise);
			if (bp == null)
				return QuickJS.Exception;

			return script->wrap_gdb_breakpoint (bp);
		}

		private async void do_gdb_add_breakpoint (GDB.Breakpoint.Kind kind, uint64 address, uint size,
				Promise<GDB.Breakpoint> promise) {
			try {
				GDB.Breakpoint bp = yield gdb.add_breakpoint (kind, address, size, io_cancellable);

				promise.resolve (bp);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private static QuickJS.Value on_gdb_run_remote_command (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			string command;
			if (!script->unparse_string (argv[0], out command))
				return QuickJS.Exception;

			var promise = new Promise<string> ();
			script->do_gdb_run_remote_command.begin (command, promise);

			string? result = script->process_events_until_ready (promise);
			if (result == null)
				return QuickJS.Exception;

			return ctx.make_string (result);
		}

		private async void do_gdb_run_remote_command (string command, Promise<string> promise) {
			try {
				string result = yield gdb.run_remote_command (command, io_cancellable);

				promise.resolve (result);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private static QuickJS.Value on_gdb_execute (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			string command;
			if (!script->unparse_string (argv[0], out command))
				return QuickJS.Exception;

			var promise = new Promise<GDB.Client> ();
			script->do_gdb_execute.begin (command, promise);

			GDB.Client? result = script->process_events_until_ready (promise);
			if (result == null)
				return QuickJS.Exception;

			return QuickJS.Undefined;
		}

		private async void do_gdb_execute (string command, Promise<GDB.Client> promise) {
			try {
				yield gdb.execute_simple (command, io_cancellable);

				promise.resolve (gdb);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private static QuickJS.Value on_gdb_query (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			string request;
			if (!script->unparse_string (argv[0], out request))
				return QuickJS.Exception;

			var promise = new Promise<GDB.Client.Packet> ();
			script->do_gdb_query.begin (request, promise);

			GDB.Client.Packet? response = script->process_events_until_ready (promise);
			if (response == null)
				return QuickJS.Exception;

			return ctx.make_string (response.payload);
		}

		private async void do_gdb_query (string request, Promise<GDB.Client.Packet> promise) {
			try {
				GDB.Client.Packet packet = yield gdb.query_simple (request, io_cancellable);

				promise.resolve (packet);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private QuickJS.Value wrap_gdb_thread (GDB.Thread thread) {
			var wrapper = ctx.make_object_class (gdb_thread_class);
			wrapper.set_opaque (thread.ref ());
			return wrapper;
		}

		private static void on_gdb_thread_finalize (QuickJS.Runtime rt, QuickJS.Value val) {
			GDB.Thread * thread = val.get_opaque (gdb_thread_class);
			thread->unref ();
		}

		private static QuickJS.Value on_gdb_thread_get_id (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			GDB.Thread * thread = this_val.get_opaque (gdb_thread_class);
			return ctx.make_string (thread->id);
		}

		private static QuickJS.Value on_gdb_thread_get_name (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			GDB.Thread * thread = this_val.get_opaque (gdb_thread_class);
			unowned string? name = thread->name;
			if (name == null)
				return QuickJS.Null;
			return ctx.make_string (name);
		}

		private static QuickJS.Value on_gdb_thread_step (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			GDB.Thread * thread = this_val.get_opaque (gdb_thread_class);

			var promise = new Promise<GDB.Thread> ();
			script->do_gdb_thread_step.begin (thread, promise);

			GDB.Thread? result = script->process_events_until_ready (promise);
			if (result == null)
				return QuickJS.Exception;

			return QuickJS.Undefined;
		}

		private async void do_gdb_thread_step (GDB.Thread thread, Promise<GDB.Thread> promise) {
			try {
				yield thread.step (io_cancellable);

				promise.resolve (thread);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private static QuickJS.Value on_gdb_thread_step_and_continue (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			GDB.Thread * thread = this_val.get_opaque (gdb_thread_class);

			try {
				thread->step_and_continue ();
			} catch (Error e) {
				script->throw_js_error (error_message_to_js (e.message));
				return QuickJS.Exception;
			}

			return QuickJS.Undefined;
		}

		private static QuickJS.Value on_gdb_thread_read_registers (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			GDB.Thread * thread = this_val.get_opaque (gdb_thread_class);

			var promise = new Promise<Gee.Map<string, Variant>> ();
			script->do_gdb_thread_read_registers.begin (thread, promise);

			Gee.Map<string, Variant> regs = script->process_events_until_ready (promise);
			if (regs == null)
				return QuickJS.Exception;

			return script->make_cpu_context (regs);
		}

		private async void do_gdb_thread_read_registers (GDB.Thread thread, Promise<Gee.Map<string, Variant>> promise) {
			try {
				Gee.Map<string, Variant> regs = yield thread.read_registers (io_cancellable);

				promise.resolve (regs);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private static QuickJS.Value on_gdb_thread_read_register (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			GDB.Thread * thread = this_val.get_opaque (gdb_thread_class);

			string name;
			if (!script->unparse_string (argv[0], out name))
				return QuickJS.Exception;

			var promise = new Promise<uint64?> ();
			script->do_gdb_thread_read_register.begin (thread, name, promise);

			uint64? val = script->process_events_until_ready (promise);
			if (val == null)
				return QuickJS.Exception;

			return script->make_native_pointer (val);
		}

		private async void do_gdb_thread_read_register (GDB.Thread thread, string name, Promise<uint64?> promise) {
			try {
				uint64 val = yield thread.read_register (name, io_cancellable);

				promise.resolve (val);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private static QuickJS.Value on_gdb_thread_write_register (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			GDB.Thread * thread = this_val.get_opaque (gdb_thread_class);

			string name;
			if (!script->unparse_string (argv[0], out name))
				return QuickJS.Exception;

			uint64 val;
			if (!script->unparse_uint64 (argv[1], out val))
				return QuickJS.Exception;

			var promise = new Promise<GDB.Thread> ();
			script->do_gdb_thread_write_register.begin (thread, name, val, promise);

			GDB.Thread? result = script->process_events_until_ready (promise);
			if (result == null)
				return QuickJS.Exception;

			return QuickJS.Undefined;
		}

		private async void do_gdb_thread_write_register (GDB.Thread thread, string name, uint64 val, Promise<GDB.Thread> promise) {
			try {
				yield thread.write_register (name, val, io_cancellable);

				promise.resolve (thread);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private QuickJS.Value wrap_gdb_breakpoint_nullable (GDB.Breakpoint? bp) {
			if (bp == null)
				return QuickJS.Null;
			return wrap_gdb_breakpoint (bp);
		}

		private QuickJS.Value wrap_gdb_breakpoint (GDB.Breakpoint bp) {
			QuickJS.Value? existing_wrapper = gdb_breakpoints[bp];
			if (existing_wrapper != null)
				return ctx.dup_value (existing_wrapper);

			var wrapper = ctx.make_object_class (gdb_breakpoint_class);
			wrapper.set_opaque (bp.ref ());
			gdb_breakpoints[bp] = wrapper;

			return wrapper;
		}

		private static void on_gdb_breakpoint_finalize (QuickJS.Runtime rt, QuickJS.Value val) {
			GDB.Breakpoint * bp = val.get_opaque (gdb_breakpoint_class);
			bp->unref ();
		}

		private static QuickJS.Value on_gdb_breakpoint_get_kind (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			GDB.Breakpoint * bp = this_val.get_opaque (gdb_breakpoint_class);
			return ctx.make_string (bp->kind.to_nick ());
		}

		private static QuickJS.Value on_gdb_breakpoint_get_address (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			GDB.Breakpoint * bp = this_val.get_opaque (gdb_breakpoint_class);
			return script->make_native_pointer (bp->address);
		}

		private static QuickJS.Value on_gdb_breakpoint_get_size (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			GDB.Breakpoint * bp = this_val.get_opaque (gdb_breakpoint_class);
			return script->ctx.make_uint32 ((uint32) bp->size);
		}

		private static QuickJS.Value on_gdb_breakpoint_enable (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			GDB.Breakpoint * bp = this_val.get_opaque (gdb_breakpoint_class);

			var promise = new Promise<GDB.Breakpoint> ();
			script->do_gdb_breakpoint_enable.begin (bp, promise);

			GDB.Breakpoint? result = script->process_events_until_ready (promise);
			if (result == null)
				return QuickJS.Exception;

			return QuickJS.Undefined;
		}

		private async void do_gdb_breakpoint_enable (GDB.Breakpoint bp, Promise<GDB.Breakpoint> promise) {
			try {
				yield bp.enable (io_cancellable);

				promise.resolve (bp);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private static QuickJS.Value on_gdb_breakpoint_disable (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			GDB.Breakpoint * bp = this_val.get_opaque (gdb_breakpoint_class);

			var promise = new Promise<GDB.Breakpoint> ();
			script->do_gdb_breakpoint_disable.begin (bp, promise);

			GDB.Breakpoint? result = script->process_events_until_ready (promise);
			if (result == null)
				return QuickJS.Exception;

			return QuickJS.Undefined;
		}

		private async void do_gdb_breakpoint_disable (GDB.Breakpoint bp, Promise<GDB.Breakpoint> promise) {
			try {
				yield bp.disable (io_cancellable);

				promise.resolve (bp);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private static QuickJS.Value on_gdb_breakpoint_remove (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			GDB.Breakpoint * bp = this_val.get_opaque (gdb_breakpoint_class);

			var promise = new Promise<GDB.Breakpoint> ();
			script->do_gdb_breakpoint_remove.begin (bp, promise);

			GDB.Breakpoint? result = script->process_events_until_ready (promise);
			if (result == null)
				return QuickJS.Exception;

			return QuickJS.Undefined;
		}

		private async void do_gdb_breakpoint_remove (GDB.Breakpoint bp, Promise<GDB.Breakpoint> promise) {
			try {
				yield bp.remove (io_cancellable);

				promise.resolve (bp);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private T? process_events_until_ready<T> (Promise<T> promise) {
			var future = promise.future;
			var main_context = MainContext.get_thread_default ();
			while (!future.ready)
				main_context.iteration (true);

			GLib.Error? error = future.error;
			if (error != null) {
				throw_js_error (error_message_to_js (error.message));
				return null;
			}

			return future.value;
		}

		private void perform_pending_io () {
			bool io_performed = false;
			do {
				io_performed = false;

				unowned QuickJS.Context? c = null;
				do {
					int res = rt.execute_pending_job (out c);
					if (res == -1)
						catch_and_emit ();
				} while (c != null);

				QuickJS.Value? cb;
				while ((cb = tick_callbacks.poll ()) != null) {
					invoke_void (cb);
					ctx.free_value (cb);

					io_performed = true;
				}
			} while (io_performed);
		}

		private bool unparse_string (QuickJS.Value val, out string str) {
			string * cstr = val.to_cstring (ctx);
			if (cstr == null) {
				str = null;
				return false;
			}
			str = cstr;
			ctx.free_cstring (cstr);
			return true;
		}

		private bool unparse_string_array (QuickJS.Value val, out Gee.List<string> strings) {
			strings = new Gee.ArrayList<string> ();

			if (!val.is_array (ctx)) {
				throw_js_error ("expected an array of strings");
				return false;
			}

			var length_val = val.get_property (ctx, length_key);
			if (length_val.is_exception ())
				return false;
			uint32 length;
			if (length_val.to_uint32 (ctx, out length) != 0)
				return false;
			ctx.free_value (length_val);

			for (uint32 i = 0; i != length; i++) {
				var element = val.get_property_uint32 (ctx, i);
				if (element.is_exception ())
					return false;
				try {
					string * cstr = element.to_cstring (ctx);
					if (cstr == null)
						return false;
					strings.add (cstr);
					ctx.free_cstring (cstr);
				} finally {
					ctx.free_value (element);
				}
			}

			return true;
		}

		private bool unparse_bool (QuickJS.Value val, out bool b) {
			b = false;

			int result = val.to_bool (ctx);
			if (result == -1)
				return false;

			b = (bool) result;
			return true;
		}

		private bool unparse_bytes (QuickJS.Value val, out Bytes bytes) {
			bytes = null;

			unowned uint8[]? data = val.get_array_buffer (ctx);

			var exception = ctx.get_exception ();
			bool buffer_is_empty = data == null && exception.is_null ();
			ctx.free_value (exception);

			bool is_array_buffer = data != null || buffer_is_empty;
			if (is_array_buffer) {
				bytes = new Bytes (data);
				return true;
			}

			size_t byte_offset = 0;
			size_t byte_length = 0;
			var buf = val.get_typed_array_buffer (ctx, &byte_offset, &byte_length);
			if (!buf.is_exception ()) {
				unowned uint8[]? whole_buf = buf.get_array_buffer (ctx);
				bytes = new Bytes (whole_buf[byte_offset:byte_offset + byte_length]);
				ctx.free_value (buf);
				return true;
			} else {
				ctx.free_value (ctx.get_exception ());
			}

			if (!val.is_array (ctx)) {
				throw_js_error ("expected a buffer-like object");
				return false;
			}

			var length_val = val.get_property (ctx, length_key);
			if (length_val.is_exception ())
				return false;
			uint32 length;
			if (length_val.to_uint32 (ctx, out length) != 0)
				return false;
			ctx.free_value (length_val);
			if (length > MAX_JS_BYTE_ARRAY_LENGTH) {
				throw_js_error ("array too large, use ArrayBuffer instead");
				return false;
			}

			var elements = new uint8[length];
			for (uint32 i = 0; i != length; i++) {
				var element = val.get_property_uint32 (ctx, i);
				if (element.is_exception ())
					return false;
				try {
					uint8 byte;
					if (!unparse_uint8 (element, out byte))
						return false;
					elements[i] = byte;
				} finally {
					ctx.free_value (element);
				}
			}
			bytes = new Bytes (elements);
			return true;
		}

		private bool unparse_uint (QuickJS.Value val, out uint uval) {
			uval = uint.MAX;

			uint32 v;
			if (val.to_uint32 (ctx, out v) != 0)
				return false;

			uval = v;
			return true;
		}

		private bool unparse_int8 (QuickJS.Value val, out int8 result) {
			result = -1;

			int32 v;
			if (!unparse_int32 (val, out v))
				return false;

			if (v < int8.MIN || v > int8.MAX) {
				throw_js_error ("expected a signed 8-bit integer");
				return false;
			}

			result = (int8) v;
			return true;
		}

		private bool unparse_uint8 (QuickJS.Value val, out uint8 result) {
			result = uint8.MAX;

			uint32 v;
			if (!unparse_uint32 (val, out v))
				return false;

			if (v > uint8.MAX) {
				throw_js_error ("expected an unsigned 8-bit integer");
				return false;
			}

			result = (uint8) v;
			return true;
		}

		private bool unparse_int16 (QuickJS.Value val, out int16 result) {
			result = -1;

			int32 v;
			if (!unparse_int32 (val, out v))
				return false;

			if (v < int16.MIN || v > int16.MAX) {
				throw_js_error ("expected a signed 16-bit integer");
				return false;
			}

			result = (int16) v;
			return true;
		}

		private bool unparse_uint16 (QuickJS.Value val, out uint16 result) {
			result = uint16.MAX;

			uint32 v;
			if (!unparse_uint32 (val, out v))
				return false;

			if (v > uint16.MAX) {
				throw_js_error ("expected an unsigned 16-bit integer");
				return false;
			}

			result = (uint16) v;
			return true;
		}

		private bool unparse_int32 (QuickJS.Value val, out int32 result) {
			return val.to_int32 (ctx, out result) == 0;
		}

		private bool unparse_uint32 (QuickJS.Value val, out uint32 result) {
			return val.to_uint32 (ctx, out result) == 0;
		}

		private bool unparse_int64 (QuickJS.Value val, out int64 result) {
			string * cstr = val.to_cstring (ctx);
			if (cstr == null) {
				result = -1;
				return false;
			}

			result = int64.parse (cstr);

			ctx.free_cstring (cstr);

			return true;
		}

		private bool unparse_uint64 (QuickJS.Value val, out uint64 result) {
			string * cstr = val.to_cstring (ctx);
			if (cstr == null) {
				result = uint64.MAX;
				return false;
			}

			result = uint64.parse (cstr);

			ctx.free_cstring (cstr);

			return true;
		}

		private bool unparse_double (QuickJS.Value val, out double result) {
			return val.to_float64 (ctx, out result) == 0;
		}

		private bool unparse_enum<T> (QuickJS.Value val, out int result) {
			result = -1;

			string * nick = val.to_cstring (ctx);
			if (nick == null)
				return false;

			try {
				result = (int) Marshal.enum_from_nick<T> (nick);
			} catch (Error e) {
				throw_js_error (error_message_to_js (e.message));
				return false;
			} finally {
				ctx.free_cstring (nick);
			}

			return true;
		}

		private bool unparse_native_pointer (QuickJS.Value val, out uint64 address) {
			address = 0;

			var v = val.get_property (ctx, v_key);
			if (v.is_exception ())
				return false;

			if (v.is_undefined ()) {
				var handle = val.get_property (ctx, handle_key);
				if (handle.is_exception ())
					return false;
				v = handle.get_property (ctx, v_key);
				if (v.is_undefined ()) {
					throw_js_error ("expected a NativePointer value");
					return false;
				}
			}

			bool success = unparse_uint64 (v, out address);

			ctx.free_value (v);

			return success;
		}

		private bool unparse_native_pointer_coercible (QuickJS.Value val, out uint64 address) {
			if (val.is_object ())
				return unparse_native_pointer (val, out address);

			var np_val = ptr_func.call (ctx, QuickJS.Undefined, { val });
			if (np_val.is_exception ()) {
				address = 0;
				return false;
			}
			bool success = unparse_native_pointer (np_val, out address);
			ctx.free_value (np_val);

			return success;
		}

		private class ValueScope {
			public unowned QuickJS.Context ctx;

			private weak BareboneScript script;
			private Gee.List<QuickJS.Value?>? values;
			private Gee.List<string *>? cstrings;

			public ValueScope (BareboneScript script) {
				this.ctx = script.ctx;
				this.script = script;
			}

			~ValueScope () {
				if (values != null) {
					foreach (var v in values)
						ctx.free_value (v);
				}
				if (cstrings != null) {
					foreach (var s in cstrings)
						ctx.free_cstring (s);
				}
			}

			public QuickJS.Value retain (QuickJS.Value v) {
				var result = ctx.dup_value (v);
				take (result);
				return result;
			}

			public QuickJS.Value take (QuickJS.Value v) {
				if (values == null)
					values = new Gee.ArrayList<QuickJS.Value?> ();
				values.add (v);
				return v;
			}

			public void release (QuickJS.Value v) {
				values.remove (v);
				ctx.free_value (v);
			}

			public string * take_cstring (string * s) {
				if (cstrings == null)
					cstrings = new Gee.ArrayList<string *> ();
				cstrings.add (s);
				return s;
			}

			public void release_cstring (string * s) {
				cstrings.remove (s);
				ctx.free_cstring (s);
			}

			public bool unparse_callback (QuickJS.Value obj, QuickJS.Atom name, out QuickJS.Value cb) {
				return do_unparse_callback (obj, name, true, out cb);
			}

			public bool unparse_optional_callback (QuickJS.Value obj, QuickJS.Atom name, out QuickJS.Value cb) {
				return do_unparse_callback (obj, name, false, out cb);
			}

			private bool do_unparse_callback (QuickJS.Value obj, QuickJS.Atom name, bool required, out QuickJS.Value cb) {
				cb = QuickJS.Undefined;

				QuickJS.Value val;
				if (!do_unparse_property (obj, name, required, out val))
					return false;

				if (required && !val.is_function (ctx)) {
					release (val);

					var name_str = name.to_cstring (ctx);
					script.throw_js_error ("expected %s to be a function".printf (name_str));
					ctx.free_cstring (name_str);

					return false;
				}

				cb = val;
				return true;
			}

			public bool unparse_optional_callback_or_pointer (QuickJS.Value obj, QuickJS.Atom name, out QuickJS.Value cb,
					out uint64 ptr) {
				return do_unparse_callback_or_pointer (obj, name, false, out cb, out ptr);
			}

			private bool do_unparse_callback_or_pointer (QuickJS.Value obj, QuickJS.Atom name, bool required,
					out QuickJS.Value cb, out uint64 ptr) {
				cb = QuickJS.Undefined;
				ptr = 0;

				QuickJS.Value val;
				if (!do_unparse_property (obj, name, required, out val))
					return false;

				if (!required && val.is_undefined ())
					return true;

				if (val.is_function (ctx)) {
					cb = val;
				} else if (!script.unparse_native_pointer (val, out ptr)) {
					script.catch_and_ignore ();

					release (val);

					var name_str = name.to_cstring (ctx);
					script.throw_js_error ("expected %s to be either a function or a pointer".p
```