Response:
### 功能归纳

该文件是Frida动态插桩工具的核心部分，主要负责与底层内存、进程、调试器（如GDB）的交互。以下是其主要功能的归纳：

1. **内存管理**：
   - **内存分配与释放**：提供了内存分配的功能，支持按页大小对齐的内存分配，并在分配后将内存初始化为零。
   - **内存扫描**：支持异步和同步的内存扫描功能，可以根据指定的内存范围和模式进行扫描，并返回匹配的地址列表。
   - **内存读写**：提供了对内存的读写操作，支持不同大小的数据类型（如8位、16位、32位、64位的有符号和无符号整数）。

2. **进程管理**：
   - **进程内存范围枚举**：可以枚举进程的内存范围，支持按内存保护属性（如读、写、执行）进行过滤。
   - **文件读写**：提供了对文件的读写操作，支持读取文件的二进制内容和文本内容，以及将二进制数据和文本写入文件。

3. **调试器交互**：
   - **GDB调试器控制**：提供了与GDB调试器的交互功能，包括继续执行、停止执行、重启调试会话等操作。
   - **断点管理**：支持设置和获取断点类型，并提供了断点的回调机制，可以在断点触发时执行自定义逻辑。

4. **拦截器（Interceptor）**：
   - **函数拦截**：支持在指定地址设置拦截器，可以在函数调用前后执行自定义逻辑。支持通过JavaScript回调或直接通过指针进行拦截。
   - **拦截器管理**：支持拦截器的附加和分离操作，并提供了对拦截器上下文的访问，如获取返回地址、线程ID、调用深度等。

5. **Rust模块加载**：
   - **Rust模块加载与执行**：支持从字符串加载Rust模块，并提供了对模块符号的解析和执行功能。模块的输出可以通过控制台进行输出。

6. **错误处理**：
   - **异常处理**：提供了对内存分配、文件读写、调试器操作等过程中可能出现的异常的处理机制，并通过JavaScript抛出异常。

### 二进制底层与Linux内核相关

- **内存管理**：涉及到底层的内存分配和释放操作，使用了页大小对齐的内存分配策略，这与Linux内核中的内存管理机制类似。
- **进程内存范围枚举**：涉及到对进程内存空间的遍历和过滤，这与Linux内核中的`/proc/[pid]/maps`文件类似，用于获取进程的内存映射信息。
- **调试器交互**：与GDB调试器的交互涉及到对进程的调试控制，如断点设置、继续执行等，这些操作通常需要与Linux内核的调试接口进行交互。

### LLDB调试示例

假设我们想要复现内存扫描的功能，可以使用LLDB的Python脚本来实现类似的功能。以下是一个简单的LLDB Python脚本示例，用于扫描内存中的特定模式：

```python
import lldb

def scan_memory(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 假设我们要扫描的内存范围和模式
    start_address = 0x100000000
    end_address = 0x200000000
    pattern = b"\x90\x90\x90"  # NOP指令的字节模式

    # 遍历内存范围
    current_address = start_address
    while current_address < end_address:
        error = lldb.SBError()
        memory = process.ReadMemory(current_address, len(pattern), error)
        if error.Success():
            if memory == pattern:
                print(f"Pattern found at address: {hex(current_address)}")
        else:
            print(f"Failed to read memory at address: {hex(current_address)}")
        current_address += 1

# 注册LLDB命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f scan_memory.scan_memory scan_memory')
```

### 假设输入与输出

- **输入**：用户调用内存扫描函数，传入内存范围（如`0x100000000`到`0x200000000`）和模式（如`"\x90\x90\x90"`）。
- **输出**：函数返回匹配的地址列表，如`[0x12345678, 0x87654321]`。

### 常见使用错误

1. **内存范围错误**：用户可能传入无效的内存范围（如负数或超出进程地址空间的范围），导致内存访问失败。
   - **示例**：`scan_memory(-100, 100, "\x90")`。
   - **错误提示**：`invalid size` 或 `invalid memory range`。

2. **模式格式错误**：用户可能传入无效的模式（如非字节字符串），导致模式匹配失败。
   - **示例**：`scan_memory(0x100000000, 0x200000000, "invalid_pattern")`。
   - **错误提示**：`invalid pattern`。

3. **回调函数错误**：用户可能传入无效的回调函数（如未定义的函数），导致回调执行失败。
   - **示例**：`scan_memory(0x100000000, 0x200000000, "\x90", {on_match: undefined})`。
   - **错误提示**：`expected one or more callbacks`。

### 用户操作路径

1. **用户启动Frida脚本**：用户通过Frida CLI或API启动一个脚本，脚本中包含对内存扫描、进程枚举等功能的调用。
2. **脚本初始化**：脚本初始化时，会加载必要的模块和服务（如内存分配器、调试器等）。
3. **用户调用功能**：用户通过JavaScript API调用内存扫描、进程枚举等功能，传入必要的参数（如内存范围、模式等）。
4. **底层交互**：Frida核心模块与底层操作系统和调试器进行交互，执行内存扫描、进程枚举等操作。
5. **结果返回**：操作完成后，结果通过JavaScript回调或返回值返回给用户。

### 调试线索

- **内存分配失败**：如果内存分配失败，可以检查分配的大小和对齐要求，确保传入的参数有效。
- **内存扫描无结果**：如果内存扫描没有返回任何结果，可以检查内存范围和模式是否正确，以及是否有权限访问目标内存。
- **调试器操作失败**：如果调试器操作（如继续执行、设置断点）失败，可以检查调试器状态和目标进程的状态，确保调试会话正常。

通过以上分析，可以更好地理解该文件的功能和使用场景，并在调试过程中快速定位和解决问题。
### 提示词
```
这是目录为frida/subprojects/frida-core/src/barebone/script.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
rn QuickJS.Exception;
			if (size == 0 || size > 0x7fffffff) {
				script->throw_js_error ("invalid size");
				return QuickJS.Exception;
			}

			var promise = new Promise<Barebone.Allocation> ();
			script->do_memory_alloc.begin (size, promise);

			Barebone.Allocation? allocation = script->process_events_until_ready (promise);
			if (allocation == null)
				return QuickJS.Exception;

			// TODO: Monitor lifetime and deallocate().

			return script->make_native_pointer (allocation.virtual_address);
		}

		private async void do_memory_alloc (size_t size, Promise<Barebone.Allocation> promise) {
			try {
				var allocator = services.allocator;
				size_t page_size = allocator.page_size;
				size_t alignment = (size % page_size) == 0 ? page_size : 16;
				var allocation = yield allocator.allocate (size, alignment, io_cancellable);

				Bytes zeroes = gdb.make_buffer_builder ()
					.skip (size)
					.build ();
				yield gdb.write_byte_array (allocation.virtual_address, zeroes, io_cancellable);

				promise.resolve (allocation);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private static QuickJS.Value on_memory_scan (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			ScanArgs? args = ScanArgs.try_parse (argv, ASYNC, script);
			if (args == null)
				return QuickJS.Exception;

			script->do_memory_scan.begin (args);

			return QuickJS.Undefined;
		}

		private async void do_memory_scan (ScanArgs args) {
			try {
				var matches =
					yield services.machine.scan_ranges (args.ranges, args.pattern, args.max_matches, io_cancellable);

				var size_val = ctx.make_uint32 ((uint32) args.pattern.size);

				foreach (uint64 address in matches) {
					var address_val = make_native_pointer (address);
					var result = invoke (args.on_match, { address_val, size_val });

					bool proceed = true;
					if (result.is_string ()) {
						string * cstr = result.to_cstring (ctx);
						if (cstr == "stop")
							proceed = false;
						ctx.free_cstring (cstr);
					}
					ctx.free_value (result);

					ctx.free_value (address_val);

					if (!proceed)
						break;
				}
			} catch (GLib.Error e) {
				if (!args.on_error.is_undefined ()) {
					var reason_val = ctx.make_string (error_message_to_js (e.message));
					invoke_void (args.on_error, { reason_val });
					ctx.free_value (reason_val);
				}
			} finally {
				if (!args.on_complete.is_undefined ())
					invoke_void (args.on_complete, {});

				perform_pending_io ();
			}
		}

		private static QuickJS.Value on_memory_scan_sync (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			ScanArgs? args = ScanArgs.try_parse (argv, SYNC, script);
			if (args == null)
				return QuickJS.Exception;

			var promise = new Promise<QuickJS.Value?> ();
			script->do_memory_scan_sync.begin (args, promise);

			QuickJS.Value? matches = script->process_events_until_ready (promise);
			if (matches == null)
				return QuickJS.Exception;

			return matches;
		}

		private async void do_memory_scan_sync (ScanArgs args, Promise<QuickJS.Value?> promise) {
			try {
				var raw_matches =
					yield services.machine.scan_ranges (args.ranges, args.pattern, args.max_matches, io_cancellable);

				var matches = ctx.make_array ();
				uint32 i = 0;
				var size_val = ctx.make_uint32 ((uint32) args.pattern.size);
				foreach (uint64 address in raw_matches) {
					var match = ctx.make_object ();
					match.set_property (ctx, address_key, make_native_pointer (address));
					match.set_property (ctx, size_key, size_val);
					matches.set_property_uint32 (ctx, i++, match);
				}

				promise.resolve (matches);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private class ScanArgs {
			public Gee.List<Gum.MemoryRange?> ranges = new Gee.ArrayList<Gum.MemoryRange?> ();
			public Barebone.MatchPattern pattern;
			public uint max_matches = 250;
			public QuickJS.Value on_match;
			public QuickJS.Value on_error;
			public QuickJS.Value on_complete;

			private ValueScope scope;

			public enum Flavor {
				ASYNC,
				SYNC
			}

			private ScanArgs (BareboneScript script) {
				scope = new ValueScope (script);
			}

			public static ScanArgs? try_parse (QuickJS.Value[] argv, Flavor flavor, BareboneScript script) {
				var args = new ScanArgs (script);

				uint64 address;
				if (!script.unparse_native_pointer (argv[0], out address))
					return null;
				uint size;
				if (!script.unparse_uint (argv[1], out size))
					return null;
				// TODO: Support passing multiple ranges
				args.ranges.add ({ address, size });

				// TODO: Handle string | MatchPattern
				string raw_pattern;
				if (!script.unparse_string (argv[2], out raw_pattern))
					return null;
				try {
					args.pattern = new Barebone.MatchPattern.from_string (raw_pattern);
				} catch (Error e) {
					script.throw_js_error (error_message_to_js (e.message));
					return null;
				}

				// TODO: Make max_matches configurable

				if (flavor == ASYNC) {
					var callbacks = argv[3];
					var scope = args.scope;

					if (!scope.unparse_callback (callbacks, script.on_match_key, out args.on_match))
						return null;

					if (!scope.unparse_optional_callback (callbacks, script.on_error_key, out args.on_error))
						return null;

					if (!scope.unparse_optional_callback (callbacks, script.on_complete_key, out args.on_complete))
						return null;
				}

				return args;
			}
		}

		private static QuickJS.Value on_process_enumerate_ranges (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			bool coalesce = false; // TODO: Propagate to Machine.enumerate_ranges()
			Gum.PageProtection prot;

			var specifier = argv[0];
			if (specifier.is_string ()) {
				if (!script->unparse_page_protection (specifier, out prot))
					return QuickJS.Exception;
			} else {
				if (!script->unparse_page_protection (specifier.get_property (ctx, script->protection_key), out prot))
					return QuickJS.Exception;
				if (!script->unparse_bool (specifier.get_property (ctx, script->coalesce_key), out coalesce))
					return QuickJS.Exception;
			}

			var promise = new Promise<QuickJS.Value?> ();
			script->do_process_enumerate_ranges.begin (prot, promise);

			QuickJS.Value? ranges = script->process_events_until_ready (promise);
			if (ranges == null)
				return QuickJS.Exception;

			return ranges;
		}

		private async void do_process_enumerate_ranges (Gum.PageProtection prot, Promise<QuickJS.Value?> promise) {
			try {
				var ranges = ctx.make_array ();

				uint32 i = 0;
				yield services.machine.enumerate_ranges (prot, r => {
					var range = ctx.make_object ();
					range.set_property (ctx, base_key, make_native_pointer (r.base_va));
					range.set_property (ctx, size_key, ctx.make_uint32 ((uint32) r.size));
					range.set_property (ctx, protection_key, parse_page_protection (r.protection));
					if (r.type != UNKNOWN)
						range.set_property (ctx, type_key, ctx.make_string (r.type.to_nick ()));
					ranges.set_property_uint32 (ctx, i++, range);
					return true;
				}, io_cancellable);

				promise.resolve (ranges);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private static QuickJS.Value on_file_read_all_bytes (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			string filename;
			if (!script->unparse_string (argv[0], out filename))
				return QuickJS.Exception;

			uint8[] contents;
			try {
				FileUtils.get_data (filename, out contents);
			} catch (FileError e) {
				script->throw_js_error (error_message_to_js (e.message));
				return QuickJS.Exception;
			}

			return script->make_array_buffer_take ((owned) contents);
		}

		private static QuickJS.Value on_file_read_all_text (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			string filename;
			if (!script->unparse_string (argv[0], out filename))
				return QuickJS.Exception;

			string contents;
			size_t length;
			try {
				FileUtils.get_contents (filename, out contents, out length);
			} catch (FileError e) {
				script->throw_js_error (error_message_to_js (e.message));
				return QuickJS.Exception;
			}

			char * end;
			if (!contents.validate ((ssize_t) length, out end)) {
				script->throw_js_error ("can't decode byte 0x%02x in position %u".printf (
					*end,
					(uint) (end - (char *) contents)));
				return QuickJS.Exception;
			}

			return ctx.make_string (contents);
		}

		private static QuickJS.Value on_file_write_all_bytes (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			string filename;
			if (!script->unparse_string (argv[0], out filename))
				return QuickJS.Exception;

			Bytes bytes;
			if (!script->unparse_bytes (argv[1], out bytes))
				return QuickJS.Exception;

			try {
				FileUtils.set_data (filename, bytes.get_data ());
			} catch (FileError e) {
				script->throw_js_error (error_message_to_js (e.message));
				return QuickJS.Exception;
			}

			return QuickJS.Undefined;
		}

		private static QuickJS.Value on_file_write_all_text (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			string filename;
			if (!script->unparse_string (argv[0], out filename))
				return QuickJS.Exception;

			string text;
			if (!script->unparse_string (argv[1], out text))
				return QuickJS.Exception;

			try {
				FileUtils.set_contents (filename, text);
			} catch (FileError e) {
				script->throw_js_error (error_message_to_js (e.message));
				return QuickJS.Exception;
			}

			return QuickJS.Undefined;
		}

		private static QuickJS.Value on_interceptor_get_breakpoint_kind (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			return script->ctx.make_string (script->services.interceptor.breakpoint_kind.to_nick ());
		}

		private static QuickJS.Value on_interceptor_set_breakpoint_kind (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			string kind;
			if (!script->unparse_string (argv[0], out kind))
				return QuickJS.Exception;

			try {
				script->services.interceptor.breakpoint_kind = GDB.Breakpoint.Kind.from_nick (kind);
			} catch (Error e) {
				script->throw_js_error (error_message_to_js (e.message));
				return QuickJS.Exception;
			}

			return QuickJS.Undefined;
		}

		private static QuickJS.Value on_interceptor_attach (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			uint64 target;
			if (!script->unparse_native_pointer (argv[0], out target))
				return QuickJS.Exception;

			Barebone.InvocationListener? listener = null;

			var scope = new ValueScope (script);

			QuickJS.Value callbacks_or_probe = scope.take (ctx.dup_value (argv[1]));

			if (callbacks_or_probe.is_function (ctx)) {
				listener = new ScriptableBreakpointInvocationListener (script, PROBE, callbacks_or_probe, QuickJS.Undefined,
					scope);
			}

			if (listener == null) {
				uint64 cb;
				if (script->unparse_native_pointer (callbacks_or_probe, out cb))
					listener = new ScriptableInlineInvocationListener (PROBE, cb, 0, scope);
				else
					script->catch_and_ignore ();
			}

			if (listener == null) {
				QuickJS.Value on_enter_js, on_leave_js;
				uint64 on_enter_ptr, on_leave_ptr;

				if (!scope.unparse_optional_callback_or_pointer (callbacks_or_probe, script->on_enter_key, out on_enter_js,
						out on_enter_ptr)) {
					return QuickJS.Exception;
				}
				if (!scope.unparse_optional_callback_or_pointer (callbacks_or_probe, script->on_leave_key, out on_leave_js,
						out on_leave_ptr)) {
					return QuickJS.Exception;
				}

				bool any_js_style = !on_enter_js.is_undefined () || !on_leave_js.is_undefined ();
				bool any_ptr_style = on_enter_ptr != 0 || on_leave_ptr != 0;
				if (any_js_style && any_ptr_style) {
					script->throw_js_error ("callbacks must be either both functions or both pointers");
					return QuickJS.Exception;
				}

				if (any_js_style) {
					listener = new ScriptableBreakpointInvocationListener (script, CALL, on_enter_js, on_leave_js,
						scope);
				} else if (any_ptr_style) {
					listener = new ScriptableInlineInvocationListener (CALL, on_enter_ptr, on_leave_ptr, scope);
				}
			}

			if (listener == null) {
				script->throw_js_error ("expected one or more callbacks");
				return QuickJS.Exception;
			}

			var promise = new Promise<Barebone.Interceptor> ();
			script->do_interceptor_attach.begin (target, listener, promise);

			Barebone.Interceptor? result = script->process_events_until_ready (promise);
			if (result == null)
				return QuickJS.Exception;

			return script->wrap_invocation_listener (listener);
		}

		private async void do_interceptor_attach (uint64 target, Barebone.InvocationListener listener,
				Promise<Barebone.Interceptor> promise) {
			try {
				var interceptor = services.interceptor;

				var bpl = listener as Barebone.BreakpointInvocationListener;
				if (bpl != null) {
					yield interceptor.attach (target, bpl, io_cancellable);
				} else {
					yield interceptor.attach_inline (target, (Barebone.InlineInvocationListener) listener,
						io_cancellable);
				}

				promise.resolve (interceptor);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private class ScriptableBreakpointInvocationListener
				: Object, Barebone.InvocationListener, Barebone.BreakpointInvocationListener {
			public Kind kind {
				get { return _kind; }
			}

			private weak BareboneScript script;
			private Kind _kind;
			private QuickJS.Value _on_enter;
			private QuickJS.Value _on_leave;
			private ValueScope scope;

			public ScriptableBreakpointInvocationListener (BareboneScript script, Kind kind, QuickJS.Value on_enter,
					QuickJS.Value on_leave, ValueScope scope) {
				this.script = script;
				this._kind = kind;
				this._on_enter = on_enter;
				this._on_leave = on_leave;
				this.scope = scope;
			}

			private void on_enter (Barebone.InvocationContext ic) {
				if (_on_enter.is_undefined ())
					return;

				var closure = new InvocationClosure (script, script.wrap_invocation_context (ic));
				var args_val = script.make_invocation_args (ic);

				script.invoke_void (_on_enter, { args_val }, closure.ic_val);

				script.destroy_wrapper (args_val);

				if (!_on_leave.is_undefined ())
					ic.user_data[this] = closure;
			}

			private void on_leave (Barebone.InvocationContext ic) {
				if (_on_leave.is_undefined ())
					return;

				var closure = (InvocationClosure?) ic.user_data[this];
				if (closure == null)
					closure = new InvocationClosure (script, script.wrap_invocation_context (ic));

				var rv_val = script.make_invocation_retval (ic);

				script.invoke_void (_on_leave, { rv_val }, closure.ic_val);

				script.destroy_wrapper (rv_val);
			}

			private class InvocationClosure : Object {
				private weak BareboneScript script;
				public QuickJS.Value ic_val;

				public InvocationClosure (BareboneScript script, QuickJS.Value ic_val) {
					this.script = script;
					this.ic_val = ic_val;
				}

				~InvocationClosure () {
					script.destroy_wrapper (ic_val);
				}
			}
		}

		private class ScriptableInlineInvocationListener
				: Object, Barebone.InvocationListener, Barebone.InlineInvocationListener {
			public Kind kind {
				get { return _kind; }
			}

			public uint64 on_enter {
				get { return _on_enter; }
			}

			public uint64 on_leave {
				get { return _on_leave; }
			}

			private Kind _kind;
			private uint64 _on_enter;
			private uint64 _on_leave;
			private ValueScope scope;

			public ScriptableInlineInvocationListener (Kind kind, uint64 on_enter, uint64 on_leave, ValueScope scope) {
				this._kind = kind;
				this._on_enter = on_enter;
				this._on_leave = on_leave;
				this.scope = scope;
			}
		}

		private QuickJS.Value wrap_invocation_listener (Barebone.InvocationListener listener) {
			var wrapper = ctx.make_object_class (invocation_listener_class);
			wrapper.set_opaque (listener);
			invocation_listeners.add (listener);
			return wrapper;
		}

		private static QuickJS.Value on_invocation_listener_detach (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			Barebone.InvocationListener * listener = this_val.get_opaque (invocation_listener_class);
			if (listener == null)
				return QuickJS.Undefined;

			var promise = new Promise<Barebone.Interceptor> ();
			script->do_invocation_listener_detach.begin (listener, promise);

			Barebone.Interceptor? result = script->process_events_until_ready (promise);
			if (result == null)
				return QuickJS.Exception;

			this_val.set_opaque (null);
			script->invocation_listeners.remove (listener);

			return QuickJS.Undefined;
		}

		private async void do_invocation_listener_detach (Barebone.InvocationListener listener,
				Promise<Barebone.Interceptor> promise) {
			try {
				var interceptor = services.interceptor;

				yield interceptor.detach (listener, io_cancellable);

				promise.resolve (interceptor);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private QuickJS.Value wrap_invocation_context (Barebone.InvocationContext ic) {
			var wrapper = ctx.make_object_class (invocation_context_class);
			wrapper.set_opaque (ic);
			return wrapper;
		}

		private bool try_unwrap_invocation_context (QuickJS.Value this_val, out Barebone.InvocationContext * ic) {
			return try_unwrap (this_val, invocation_context_class, out ic);
		}

		private static QuickJS.Value on_invocation_context_get_return_address (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			Barebone.InvocationContext * ic;
			if (!script->try_unwrap_invocation_context (this_val, out ic))
				return QuickJS.Exception;

			return script->make_native_pointer (ic->return_address);
		}

		private static QuickJS.Value on_invocation_context_get_context (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			Barebone.InvocationContext * ic;
			if (!script->try_unwrap_invocation_context (this_val, out ic))
				return QuickJS.Exception;

			return script->make_cpu_context (ic->registers);
		}

		private static QuickJS.Value on_invocation_context_get_thread_id (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			Barebone.InvocationContext * ic;
			if (!script->try_unwrap_invocation_context (this_val, out ic))
				return QuickJS.Exception;

			return script->ctx.make_string (ic->thread_id);
		}

		private static QuickJS.Value on_invocation_context_get_depth (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			Barebone.InvocationContext * ic;
			if (!script->try_unwrap_invocation_context (this_val, out ic))
				return QuickJS.Exception;

			return script->ctx.make_uint32 (ic->depth);
		}

		private QuickJS.Value make_invocation_args (Barebone.InvocationContext ic) {
			var wrapper = ctx.make_object_class (invocation_args_class);
			wrapper.set_opaque (ic);
			return wrapper;
		}

		private bool try_unwrap_invocation_args (QuickJS.Value this_val, out Barebone.InvocationContext * ic) {
			return try_unwrap (this_val, invocation_args_class, out ic);
		}

		private static QuickJS.Value on_invocation_args_get_property (QuickJS.Context ctx, QuickJS.Value obj, QuickJS.Atom atom,
				QuickJS.Value receiver) {
			BareboneScript * script = ctx.get_opaque ();

			Barebone.InvocationContext * ic;
			if (!script->try_unwrap_invocation_args (obj, out ic))
				return QuickJS.Exception;

			QuickJS.Value result = QuickJS.Undefined;

			string * name = atom.to_cstring (ctx);
			uint n;
			if (uint.try_parse (name, out n))
				result = script->make_native_pointer (ic->get_nth_argument (n));
			ctx.free_cstring (name);

			return result;
		}

		private static int on_invocation_args_set_property (QuickJS.Context ctx, QuickJS.Value obj, QuickJS.Atom atom,
				QuickJS.Value val, QuickJS.Value receiver, QuickJS.PropertyFlags flags) {
			BareboneScript * script = ctx.get_opaque ();

			Barebone.InvocationContext * ic;
			if (!script->try_unwrap_invocation_args (obj, out ic))
				return -1;

			string * name = atom.to_cstring (ctx);
			try {
				uint n;
				if (uint.try_parse (name, out n)) {
					uint64 raw_val;
					if (!script->unparse_native_pointer (val, out raw_val))
						return -1;
					ic->replace_nth_argument (n, raw_val);
				}
			} finally {
				ctx.free_cstring (name);
			}

			return 0;
		}

		private QuickJS.Value make_invocation_retval (Barebone.InvocationContext ic) {
			var wrapper = ctx.make_object_class (invocation_retval_class);
			wrapper.set_opaque (ic);
			wrapper.set_property (ctx, v_key, ctx.make_biguint64 (ic.get_return_value ()));
			return wrapper;
		}

		private static QuickJS.Value on_invocation_retval_replace (QuickJS.Context ctx, QuickJS.Value this_val,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			Barebone.InvocationContext * ic;
			if (!script->try_unwrap (this_val, invocation_retval_class, out ic))
				return QuickJS.Exception;

			uint64 raw_val;
			if (!script->unparse_native_pointer_coercible (argv[0], out raw_val))
				return QuickJS.Exception;

			this_val.set_property (ctx, script->v_key, ctx.make_biguint64 (raw_val));

			ic->replace_return_value (raw_val);

			return QuickJS.Undefined;
		}

		private static QuickJS.Value on_rust_module_construct (QuickJS.Context ctx, QuickJS.Value new_target,
				QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			var scope = new ValueScope (script);

			string source;
			if (!script->unparse_string (argv[0], out source))
				return QuickJS.Exception;

			var symbols = new Gee.HashMap<string, uint64?> ();
			var symbols_obj = argv[1];
			if (!symbols_obj.is_undefined ()) {
				QuickJS.PropertyEnum * tab;
				uint32 n;
				if (symbols_obj.get_own_property_names (ctx, out tab, out n, STRING_MASK | ENUM_ONLY) != 0)
					return QuickJS.Exception;
				unowned QuickJS.PropertyEnum[] entries = ((QuickJS.PropertyEnum[]) tab)[:n];

				try {
					foreach (var e in entries) {
						string * name = scope.take_cstring (e.atom.to_cstring (ctx));

						uint64 address;
						QuickJS.Value val = scope.take (symbols_obj.get_property (ctx, e.atom));
						if (!script->unparse_native_pointer (val, out address))
							return QuickJS.Exception;

						symbols[name] = address;

						scope.release_cstring (name);
					}
				} finally {
					foreach (var e in entries)
						ctx.free_atom (e.atom);
					ctx.free (tab);
				}
			}

			Gee.List<string> dependencies = new Gee.ArrayList<string> ();
			var options_obj = argv[2];
			if (!options_obj.is_undefined ()) {
				QuickJS.Value dependencies_val = options_obj.get_property (ctx, script->dependencies_key);
				if (dependencies_val.is_exception ())
					return QuickJS.Exception;
				if (!dependencies_val.is_undefined () && !script->unparse_string_array (dependencies_val, out dependencies))
					return QuickJS.Exception;
			}

			var promise = new Promise<Barebone.RustModule> ();
			script->load_rust_module.begin (source, symbols, dependencies, promise);

			Barebone.RustModule? mod = script->process_events_until_ready (promise);
			if (mod == null)
				return QuickJS.Exception;

			if (!symbols.is_empty)
				mod.set_data ("value-scope", (owned) scope);

			var proto = new_target.get_property (ctx, script->prototype_key);
			var wrapper = ctx.make_object_with_proto_and_class (proto, rust_module_class);
			ctx.free_value (proto);

			wrapper.set_opaque (mod);
			script->rust_modules.add (mod);

			foreach (var e in mod.exports)
				wrapper.set_property_str (ctx, e.name, script->make_native_pointer (e.address));

			mod.console_output.connect (script->on_rust_module_console_output);

			return wrapper;
		}

		private async void load_rust_module (string source, Gee.Map<string, uint64?> symbols, Gee.List<string> dependencies,
				Promise<Barebone.RustModule> promise) {
			try {
				var mod = yield new Barebone.RustModule.from_string (source, symbols, dependencies, services.machine,
					services.allocator, io_cancellable);

				promise.resolve (mod);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private static void on_rust_module_finalize (QuickJS.Runtime rt, QuickJS.Value val) {
			Barebone.RustModule * mod = val.get_opaque (rust_module_class);
			if (mod == null)
				return;

			BareboneScript * script = rt.get_opaque ();
			script->rust_modules.remove (mod);
		}

		private static QuickJS.Value on_rust_module_dispose (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			Barebone.RustModule * mod = this_val.get_opaque (rust_module_class);

			if (mod != null) {
				this_val.set_opaque (null);
				BareboneScript * script = ctx.get_opaque ();
				script->rust_modules.remove (mod);
			}

			return QuickJS.Undefined;
		}

		private void on_rust_module_console_output (string message) {
			var builder = new Json.Builder ();
			builder
				.begin_object ()
					.set_member_name ("type")
					.add_string_value ("log")
					.set_member_name ("level")
					.add_string_value ("info")
					.set_member_name ("payload")
					.add_string_value (message)
				.end_object ();
			this.message (Json.to_string (builder.get_root (), false), null);
		}

		private static QuickJS.Value on_gdb_get_state (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			return ctx.make_string (script->gdb.state.to_nick ());
		}

		private static QuickJS.Value on_gdb_get_exception (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			GDB.Exception? exception = script->gdb.exception;
			if (exception == null)
				return QuickJS.Null;

			var result = ctx.make_object ();
			result.set_property (ctx, script->signum_key, ctx.make_uint32 (exception.signum));
			result.set_property (ctx, script->breakpoint_key, script->wrap_gdb_breakpoint_nullable (exception.breakpoint));
			result.set_property (ctx, script->thread_key, script->wrap_gdb_thread (exception.thread));
			return result;
		}

		private static QuickJS.Value on_gdb_continue (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			var promise = new Promise<GDB.Client> ();
			script->do_gdb_continue.begin (promise);

			GDB.Client? client = script->process_events_until_ready (promise);
			if (client == null)
				return QuickJS.Exception;

			return QuickJS.Undefined;
		}

		private async void do_gdb_continue (Promise<GDB.Client> promise) {
			try {
				yield gdb.continue (io_cancellable);

				promise.resolve (gdb);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private static QuickJS.Value on_gdb_stop (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			var promise = new Promise<GDB.Client> ();
			script->do_gdb_stop.begin (promise);

			GDB.Client? client = script->process_events_until_ready (promise);
			if (client == null)
				return QuickJS.Exception;

			return QuickJS.Undefined;
		}

		private async void do_gdb_stop (Promise<GDB.Client> promise) {
			try {
				yield gdb.stop (io_cancellable);

				promise.resolve (gdb);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private static QuickJS.Value on_gdb_restart (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();

			try {
				script->gdb.restart ();
			} catch (Error e) {
				script->throw_js_error (error_message_to_js (e.message));
				return QuickJS.Exception;
			}

			return QuickJS.Undefined;
		}

		private static QuickJS.Value on_gdb_read_pointer (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_read (ctx, this_val, argv, script->gdb.pointer_size, script->parse_raw_pointer);
		}

		private static QuickJS.Value on_gdb_write_pointer (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_write (ctx, this_val, argv, script->unparse_raw_pointer);
		}

		private static QuickJS.Value on_gdb_read_s8 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_read (ctx, this_val, argv, 1, script->parse_raw_s8);
		}

		private static QuickJS.Value on_gdb_write_s8 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_write (ctx, this_val, argv, script->unparse_raw_s8);
		}

		private static QuickJS.Value on_gdb_read_u8 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_read (ctx, this_val, argv, 1, script->parse_raw_u8);
		}

		private static QuickJS.Value on_gdb_write_u8 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_write (ctx, this_val, argv, script->unparse_raw_u8);
		}

		private static QuickJS.Value on_gdb_read_s16 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_read (ctx, this_val, argv, 2, script->parse_raw_s16);
		}

		private static QuickJS.Value on_gdb_write_s16 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_write (ctx, this_val, argv, script->unparse_raw_s16);
		}

		private static QuickJS.Value on_gdb_read_u16 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_read (ctx, this_val, argv, 2, script->parse_raw_u16);
		}

		private static QuickJS.Value on_gdb_write_u16 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_write (ctx, this_val, argv, script->unparse_raw_u16);
		}

		private static QuickJS.Value on_gdb_read_s32 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_read (ctx, this_val, argv, 4, script->parse_raw_s32);
		}

		private static QuickJS.Value on_gdb_write_s32 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_write (ctx, this_val, argv, script->unparse_raw_s32);
		}

		private static QuickJS.Value on_gdb_read_u32 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_read (ctx, this_val, argv, 4, script->parse_raw_u32);
		}

		private static QuickJS.Value on_gdb_write_u32 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_write (ctx, this_val, argv, script->unparse_raw_u32);
		}

		private static QuickJS.Value on_gdb_read_s64 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_read (ctx, this_val, argv, 8, script->parse_raw_s64);
		}

		private static QuickJS.Value on_gdb_write_s64 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_write (ctx, this_val, argv, script->unparse_raw_s64);
		}

		private static QuickJS.Value on_gdb_read_u64 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_read (ctx, this_val, argv, 8, script->parse_raw_u64);
		}

		private static QuickJS.Value on_gdb_write_u64 (QuickJS.Context ctx, QuickJS.Value this_val, QuickJS.Value[] argv) {
			BareboneScript * script = ctx.get_opaque ();
			return script->do_gdb_write (ctx, this_val, argv, script->unparse_raw_u64);
		}

		private static Q
```