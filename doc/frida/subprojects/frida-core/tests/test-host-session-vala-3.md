Response:
### 功能归纳

`test-host-session.vala` 是 Frida 动态插桩工具的核心测试文件之一，主要用于测试 Frida 的 `HostSession` 功能。`HostSession` 是 Frida 的核心组件之一，负责与目标进程进行交互，包括进程的创建、附加、脚本注入、消息传递等操作。该测试文件通过模拟不同的场景来验证 `HostSession` 的正确性和稳定性。

以下是该文件的主要功能归纳：

1. **进程创建与附加测试**：
   - 测试通过 `DeviceManager` 创建和附加到目标进程的功能。
   - 验证子进程的创建、父进程与子进程的分离、子进程的路径、命令行参数等信息的正确性。
   - 通过 `spawn` 和 `attach` 方法创建和附加到目标进程，并验证进程的状态。

2. **脚本注入与消息传递测试**：
   - 测试在目标进程中注入脚本并接收来自脚本的消息。
   - 通过 `Interceptor.attach` 拦截目标函数（如 `GetMessageW` 和 `OutputDebugStringW`），并验证拦截到的消息是否正确。
   - 验证脚本注入后，目标进程的行为是否符合预期。

3. **大消息处理测试**：
   - 测试处理大消息的能力，验证 Frida 是否能够正确处理大尺寸的消息传递。
   - 通过发送不同大小的消息（如 1024、4096、8192、16384、32768 字节）并验证接收到的消息是否正确。

4. **iOS 设备连接与操作测试**：
   - 测试与 iOS 设备的连接、应用程序的枚举、进程的启动与附加等功能。
   - 通过 `FruityHostSessionBackend` 与 iOS 设备进行交互，验证设备信息的获取、应用程序的启动、脚本注入等功能。

5. **Android 设备连接与操作测试**：
   - 测试与 Android 设备的连接、进程的枚举、脚本注入等功能。
   - 通过 `DroidyHostSessionBackend` 与 Android 设备进行交互，验证设备信息的获取、进程的枚举、脚本注入等功能。

6. **Plist 文件处理测试**：
   - 测试从 XML 文档构造 Plist 文件，并验证 Plist 文件的正确性。
   - 验证 Plist 文件的序列化与反序列化功能，确保 Plist 文件能够正确表示复杂的数据结构。

### 二进制底层与 Linux 内核相关

- **进程创建与附加**：在 Linux 系统中，进程的创建和附加涉及到 `fork`、`exec`、`ptrace` 等系统调用。Frida 通过这些系统调用来实现对目标进程的控制和调试。
- **脚本注入**：Frida 通过 `ptrace` 或 `LD_PRELOAD` 等技术将动态库注入到目标进程中，从而实现函数拦截和修改。在 Linux 内核中，`ptrace` 是一个关键的系统调用，用于进程调试和控制。
- **消息传递**：Frida 使用共享内存或管道等技术在目标进程和调试器之间传递消息。这些技术依赖于 Linux 内核提供的进程间通信机制。

### LLDB 调试示例

假设我们想要复现 Frida 的脚本注入功能，可以使用 LLDB 来调试目标进程并注入代码。以下是一个简单的 LLDB Python 脚本示例，用于在目标进程中注入代码并拦截函数调用：

```python
import lldb

def inject_code(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 获取目标函数的地址
    target_function = frame.FindFunction("GetMessageW")
    if not target_function.IsValid():
        result.AppendMessage("Failed to find GetMessageW function")
        return

    # 在目标函数入口处设置断点
    breakpoint = target.BreakpointCreateByAddress(target_function.GetStartAddress().GetLoadAddress(target))
    if not breakpoint.IsValid():
        result.AppendMessage("Failed to set breakpoint at GetMessageW")
        return

    # 断点触发时的回调函数
    def breakpoint_callback(frame, bp_loc, dict):
        print("GetMessageW called!")
        # 在这里可以执行自定义的代码
        return True

    # 设置断点回调
    breakpoint.SetScriptCallbackFunction("breakpoint_callback")

    # 继续执行目标进程
    process.Continue()

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f inject_code.inject_code inject_code')
```

### 假设输入与输出

- **输入**：目标进程的 PID 或可执行文件路径。
- **输出**：在目标进程调用 `GetMessageW` 函数时，输出 "GetMessageW called!"，并执行自定义的代码。

### 用户常见错误

1. **权限不足**：在 Linux 系统中，调试其他进程需要 root 权限。如果用户没有足够的权限，`ptrace` 调用会失败。
   - **解决方法**：使用 `sudo` 或以 root 用户身份运行调试器。

2. **目标进程崩溃**：在注入代码时，如果代码有误或内存访问越界，可能导致目标进程崩溃。
   - **解决方法**：确保注入的代码正确无误，并在调试器中逐步验证。

3. **断点未触发**：如果断点设置不正确或目标函数未被调用，断点可能不会触发。
   - **解决方法**：检查断点设置是否正确，并确保目标函数被调用。

### 用户操作步骤

1. **启动目标进程**：用户启动目标进程，并获取其 PID。
2. **附加调试器**：用户使用 LLDB 或 GDB 附加到目标进程。
3. **注入代码**：用户运行调试脚本，注入代码并设置断点。
4. **触发断点**：用户操作目标进程，触发断点并执行自定义代码。
5. **验证输出**：用户验证调试器输出是否符合预期。

### 总结

`test-host-session.vala` 文件通过模拟不同的场景来测试 Frida 的核心功能，包括进程创建、脚本注入、消息传递等。通过这些测试，Frida 能够确保其在不同平台和设备上的稳定性和正确性。用户在使用 Frida 时，可以通过调试器（如 LLDB）复现这些功能，并验证目标进程的行为。
### 提示词
```
这是目录为frida/subprojects/frida-core/tests/test-host-session.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```
UTPUT_HANDLE = -11;
					const winAbi = (Process.pointerSize === 4) ? 'stdcall' : 'win64';
					const GetStdHandle = new NativeFunction(Module.getExportByName('kernel32.dll', 'GetStdHandle'), 'pointer', ['int'], winAbi);
					const WriteFile = new NativeFunction(Module.getExportByName('kernel32.dll', 'WriteFile'), 'int', ['pointer', 'pointer', 'uint', 'pointer', 'pointer'], winAbi);
					const stdout = GetStdHandle(STD_OUTPUT_HANDLE);
					const message = Memory.allocUtf8String('Hello stdout');
					const success = WriteFile(stdout, message, 12, NULL, NULL);
					Interceptor.attach(Module.getExportByName('user32.dll', 'GetMessageW'), {
					  onEnter(args) {
					    send('GetMessage');
					  }
					});
					""", make_parameters_dict (), cancellable);
				yield session.load_script (script_id, cancellable);

				if (received_output == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (received_output == "Hello stdout");
				host_session.disconnect (output_handler);

				yield host_session.resume (pid, cancellable);

				if (received_message == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (received_message == "{\"type\":\"send\",\"payload\":\"GetMessage\"}");
				h.disconnect (message_handler);

				yield host_session.kill (pid, cancellable);
			} catch (GLib.Error e) {
				printerr ("Unexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void create_process (Harness h) {
			if (sizeof (void *) == 8 && !GLib.Test.slow ()) {
				stdout.printf ("<skipping due to pending 64-bit issue, run in slow mode> ");
				h.done ();
				return;
			}

			var target_path = Frida.Test.Labrats.path_to_executable ("spawner");
			var method = "CreateProcess";

			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

				string parent_detach_reason = null;
				string child_detach_reason = null;
				var child_messages = new Gee.ArrayList<string> ();
				Child the_child = null;
				bool waiting = false;

				if (GLib.Test.verbose ()) {
					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});
				}
				device.child_added.connect (child => {
					the_child = child;
					if (waiting)
						create_process.callback ();
				});

				var options = new SpawnOptions ();
				options.argv = { target_path, "spawn", method };
				options.stdio = PIPE;
				var parent_pid = yield device.spawn (target_path, options);
				var parent_session = yield device.attach (parent_pid);
				parent_session.detached.connect (reason => {
					parent_detach_reason = reason.to_string ();
					if (waiting)
						create_process.callback ();
				});
				yield parent_session.enable_child_gating ();

				yield device.resume (parent_pid);

				while (the_child == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				var child = the_child;
				the_child = null;
				assert_true (child.pid != parent_pid);
				assert_true (child.parent_pid == parent_pid);
				assert_true (child.origin == SPAWN);
				assert_null (child.identifier);
				assert_nonnull (child.path);
				assert_true (Path.get_basename (child.path).has_prefix ("spawner-"));
				assert_nonnull (child.argv);
				assert_null (child.envp);

				assert_null (parent_detach_reason);

				var child_session = yield device.attach (child.pid);
				child_session.detached.connect (reason => {
					child_detach_reason = reason.to_string ();
					if (waiting)
						create_process.callback ();
				});
				var script = yield child_session.create_script ("""
					Interceptor.attach(Module.getExportByName('kernel32.dll', 'OutputDebugStringW'), {
					  onEnter(args) {
					    send(args[0].readUtf16String());
					  }
					});
					""");
				script.message.connect ((message, data) => {
					if (GLib.Test.verbose ())
						printerr ("Message from child: %s\n", message);
					child_messages.add (message);
					if (waiting)
						create_process.callback ();
				});
				yield script.load ();

				yield device.resume (child.pid);

				while (child_messages.is_empty) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_messages.size == 1);
				assert_true (parse_string_message_payload (child_messages[0]) == method);

				while (child_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				while (parent_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (parent_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				yield h.process_events ();
				assert_true (child_messages.size == 1);

				yield device_manager.close ();

				h.done ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

	}
#endif
#endif // HAVE_LOCAL_BACKEND

#if HAVE_FRUITY_BACKEND
	namespace Fruity {

		private static async void backend (Harness h) {
			if (!GLib.Test.slow ()) {
				stdout.printf ("<skipping, run in slow mode with iOS device connected> ");
				h.done ();
				return;
			}

			var backend = new FruityHostSessionBackend ();

			var prov = yield h.setup_remote_backend (backend);

#if WINDOWS
			assert_true (prov.name != "iOS Device"); /* should manage to extract a user-defined name */
#endif

			Variant? icon = prov.icon;
			if (icon != null) {
				var dict = new VariantDict (icon);
				int64 width, height;
				assert_true (dict.lookup ("width", "x", out width));
				assert_true (dict.lookup ("height", "x", out height));
				assert_true (width == 16);
				assert_true (height == 16);
				VariantIter image;
				assert_true (dict.lookup ("image", "ay", out image));
				assert_true (image.n_children () == width * height * 4);
			}

			try {
				Cancellable? cancellable = null;

				var session = yield prov.create (null, cancellable);
				var processes = yield session.enumerate_processes (make_parameters_dict (), cancellable);
				assert_true (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void large_messages (Harness h) {
			if (!GLib.Test.slow ()) {
				stdout.printf ("<skipping, run in slow mode with iOS device connected> ");
				h.done ();
				return;
			}

			var backend = new FruityHostSessionBackend ();

			var prov = yield h.setup_remote_backend (backend);

			try {
				Cancellable? cancellable = null;

				stdout.printf ("connecting to frida-server\n");
				var host_session = yield prov.create (null, cancellable);
				stdout.printf ("enumerating processes\n");
				var processes = yield host_session.enumerate_processes (make_parameters_dict (), cancellable);
				assert_true (processes.length > 0);

				HostProcessInfo? process = null;
				foreach (var p in processes) {
					if (p.name == "hello-frida") {
						process = p;
						break;
					}
				}
				assert_nonnull ((void *) process);

				stdout.printf ("attaching to target process\n");
				var session_id = yield host_session.attach (process.pid, make_parameters_dict (), cancellable);
				var session = yield prov.link_agent_session (host_session, session_id, h, cancellable);
				string received_message = null;
				var message_handler = h.message_from_script.connect ((script_id, json, data) => {
					received_message = json;
					large_messages.callback ();
				});
				stdout.printf ("creating script\n");
				var script_id = yield session.create_script ("""
					function onMessage(message) {
					  send('ACK: ' + message.length);
					  recv(onMessage);
					}
					recv(onMessage);
					""", make_parameters_dict (), cancellable);
				stdout.printf ("loading script\n");
				yield session.load_script (script_id, cancellable);
				var steps = new uint[] { 1024, 4096, 8192, 16384, 32768 };
				var transport_overhead = 163;
				foreach (var step in steps) {
					var builder = new StringBuilder ();
					builder.append ("\"");
					for (var i = 0; i != step - transport_overhead; i++) {
						builder.append ("s");
					}
					builder.append ("\"");
					yield session.post_messages ({ AgentMessage (SCRIPT, script_id, builder.str, false, {}) }, 0,
						cancellable);
					yield;
					stdout.printf ("received message: '%s'\n", received_message);
				}
				h.disconnect (message_handler);

				yield session.destroy_script (script_id, cancellable);
				yield session.close (cancellable);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		namespace Manual {

			private const string DEVICE_ID = "<device-id>";
			private const string APP_ID = "<app-id>";

			private static async void lockdown (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode with iOS device connected> ");
					h.done ();
					return;
				}

				h.disable_timeout ();

				string? target_name = null;
				uint target_pid = 0;

				var device_manager = new DeviceManager ();

				try {
					var device = yield device_manager.get_device_by_id (DEVICE_ID);

					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});

					var timer = new Timer ();

					printerr ("device.query_system_parameters()");
					timer.reset ();
					var p = yield device.query_system_parameters ();
					printerr (" => got parameters, took %u ms\n", (uint) (timer.elapsed () * 1000.0));
					var iter = HashTableIter<string, Variant> (p);
					string k;
					Variant v;
					while (iter.next (out k, out v))
						printerr ("%s: %s\n", k, v.print (false));

					printerr ("device.enumerate_applications()");
					timer.reset ();
					var opts = new ApplicationQueryOptions ();
					opts.scope = FULL;
					var apps = yield device.enumerate_applications (opts);
					printerr (" => got %d apps, took %u ms\n", apps.size (), (uint) (timer.elapsed () * 1000.0));
					if (GLib.Test.verbose ()) {
						var length = apps.size ();
						for (int i = 0; i != length; i++) {
							var app = apps.get (i);
							printerr ("\t%s\n", app.identifier);
						}
					}

					if (target_name != null) {
						timer.reset ();
						var process = yield device.get_process_by_name (target_name);
						target_pid = process.pid;
						printerr (" => resolved to pid=%u, took %u ms\n", target_pid, (uint) (timer.elapsed () * 1000.0));
					}

					uint pid;
					if (target_pid != 0) {
						pid = target_pid;
					} else {
						printerr ("device.spawn()");
						timer.reset ();
						pid = yield device.spawn (APP_ID);
						printerr (" => pid=%u, took %u ms\n", pid, (uint) (timer.elapsed () * 1000.0));
					}

					printerr ("device.attach(pid=%u)", pid);
					timer.reset ();
					var session = yield device.attach (pid);
					printerr (" => took %u ms\n", (uint) (timer.elapsed () * 1000.0));

					printerr ("session.create_script()");
					timer.reset ();
					var script = yield session.create_script ("""
						send(Module.getExportByName(null, 'open'));
						""");
					printerr (" => took %u ms\n", (uint) (timer.elapsed () * 1000.0));

					string received_message = null;
					bool waiting = false;
					script.message.connect ((message, data) => {
						received_message = message;
						if (waiting)
							lockdown.callback ();
					});

					printerr ("script.load()");
					timer.reset ();
					yield script.load ();
					printerr (" => took %u ms\n", (uint) (timer.elapsed () * 1000.0));

					printerr ("await_message()");
					while (received_message == null) {
						waiting = true;
						yield;
						waiting = false;
					}
					printerr (" => received_message: %s\n", received_message);
					received_message = null;

					if (target_pid == 0) {
						printerr ("device.resume(pid=%u)", pid);
						timer.reset ();
						yield device.resume (pid);
						printerr (" => took %u ms\n", (uint) (timer.elapsed () * 1000.0));
					}

					yield h.prompt_for_key ("Hit a key to exit: ");
				} catch (GLib.Error e) {
					printerr ("\nFAIL: %s\n\n", e.message);
				}

				try {
					yield device_manager.close ();
				} catch (IOError e) {
					assert_not_reached ();
				}

				h.done ();
			}

			namespace Xpc {

				private static async void list (Harness h) {
					if (!GLib.Test.slow ()) {
						stdout.printf ("<skipping, run in slow mode with iOS device connected> ");
						h.done ();
						return;
					}

					var device_manager = new DeviceManager ();

					try {
						var timer = new Timer ();
						var device = yield device_manager.get_device_by_id (DEVICE_ID);
						printerr ("[*] Got device in %u ms\n", (uint) (timer.elapsed () * 1000.0));

						timer.reset ();
						var appservice = yield device.open_service ("xpc:com.apple.coredevice.appservice");
						printerr ("[*] Opened service in %u ms\n", (uint) (timer.elapsed () * 1000.0));

						var parameters = new HashTable<string, Variant> (str_hash, str_equal);
						parameters["CoreDevice.featureIdentifier"] = "com.apple.coredevice.feature.listprocesses";
						parameters["CoreDevice.action"] = new HashTable<string, Variant> (str_hash, str_equal);
						parameters["CoreDevice.input"] = new HashTable<string, Variant> (str_hash, str_equal);
						timer.reset ();
						var response = yield appservice.request (parameters);
						printerr ("[*] Made request in %u ms\n", (uint) (timer.elapsed () * 1000.0));
						printerr ("Got response: %s\n", response.print (true));
					} catch (GLib.Error e) {
						printerr ("\nFAIL: %s\n\n", e.message);
						yield;
					}

					h.done ();
				}

				private static async void launch (Harness h) {
					if (!GLib.Test.slow ()) {
						stdout.printf ("<skipping, run in slow mode with iOS device connected> ");
						h.done ();
						return;
					}

					var device_manager = new DeviceManager ();

					try {
						var timer = new Timer ();
						var device = yield device_manager.get_device_by_id (DEVICE_ID);
						printerr ("[*] Got device in %u ms\n", (uint) (timer.elapsed () * 1000.0));

						timer.reset ();
						var appservice = yield device.open_service ("xpc:com.apple.coredevice.appservice");
						printerr ("[*] Opened service in %u ms\n", (uint) (timer.elapsed () * 1000.0));

						var stdio_stream = yield device.open_channel ("tcp:com.apple.coredevice.openstdiosocket");
						uint8 stdio_uuid[16];
						size_t n;
						yield stdio_stream.get_input_stream ().read_all_async (stdio_uuid, Priority.DEFAULT, null, out n);

						var parameters = new HashTable<string, Variant> (str_hash, str_equal);
						parameters["CoreDevice.featureIdentifier"] = "com.apple.coredevice.feature.launchapplication";
						parameters["CoreDevice.action"] = new HashTable<string, Variant> (str_hash, str_equal);

						var standard_input = Variant.new_from_data<void> (new VariantType ("ay"), stdio_uuid, true);
						var standard_output = standard_input;
						var standard_error = standard_output;
						var input = new Variant.parsed (@"""{
								'applicationSpecifier': <{
									'bundleIdentifier': <{
										'_0': <'$APP_ID'>
									}>
								}>,
								'options': <{
									'arguments': <@av []>,
									'environmentVariables': <@a{sv} {}>,
									'standardIOUsesPseudoterminals': <true>,
									'startStopped': <false>,
									'terminateExisting': <true>,
									'user': <{
										'active': <true>
									}>,
									'platformSpecificOptions': <
										b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict/></plist>'
									>
								}>,
								'standardIOIdentifiers': <{
									'standardInput': <('uuid', %@ay)>,
									'standardOutput': <('uuid', %@ay)>,
									'standardError': <('uuid', %@ay)>
								}>
							}""",
							standard_input,
							standard_output,
							standard_error);
						printerr ("input: %s\n", input.print (true));
						parameters["CoreDevice.input"] = input;
						timer.reset ();
						var response = yield appservice.request (parameters);
						printerr ("[*] Made request in %u ms\n", (uint) (timer.elapsed () * 1000.0));
						printerr ("Got response: %s\n", response.print (true));

						process_stdio.begin (stdio_stream);

						// Wait forever...
						h.disable_timeout ();
						yield;
					} catch (GLib.Error e) {
						printerr ("\nFAIL: %s\n\n", e.message);
						yield;
					}

					h.done ();
				}

				private async void process_stdio (IOStream stream) {
					try {
						var input = new DataInputStream (stream.get_input_stream ());
						while (true) {
							var line = yield input.read_line_async ();
							if (line == null) {
								printerr ("process_stdio: EOF\n");
								break;
							}
							printerr ("process_stdio got line: %s\n", line);
						}
					} catch (GLib.Error e) {
						printerr ("process_stdio: %s\n", e.message);
					}
				}

			}

		}

		namespace Plist {

			private static void can_construct_from_xml_document () {
				var xml = """
					<?xml version="1.0" encoding="UTF-8"?>
					<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
					<plist version="1.0">
					<dict>
						<key>DeviceID</key>
						<integer>2</integer>
						<key>MessageType</key>
						<string>Attached</string>
						<key>Properties</key>
						<dict>
							<key>ConnectionType</key>
							<string>USB</string>
							<key>DeviceID</key>
							<integer>2</integer>
							<key>LocationID</key>
							<integer>0</integer>
							<key>ProductID</key>
							<integer>4759</integer>
							<key>SerialNumber</key>
							<string>220f889780dda462091a65df48b9b6aedb05490f</string>
							<key>ExtraBoolTrue</key>
							<true/>
							<key>ExtraBoolFalse</key>
							<false/>
							<key>ExtraData</key>
							<data>AQID</data>
							<key>ExtraStrings</key>
							<array>
								<string>A</string>
								<string>B</string>
							</array>
						</dict>
					</dict>
					</plist>
				""";

				try {
					var plist = new Frida.Fruity.Plist.from_xml (xml);
					assert_true (plist.size == 3);
					assert_true (plist.get_integer ("DeviceID") == 2);
					assert_true (plist.get_string ("MessageType") == "Attached");

					var properties = plist.get_dict ("Properties");
					assert_true (properties.size == 9);
					assert_true (properties.get_string ("ConnectionType") == "USB");
					assert_true (properties.get_integer ("DeviceID") == 2);
					assert_true (properties.get_integer ("LocationID") == 0);
					assert_true (properties.get_integer ("ProductID") == 4759);
					assert_true (properties.get_string ("SerialNumber") == "220f889780dda462091a65df48b9b6aedb05490f");

					assert_true (properties.get_boolean ("ExtraBoolTrue") == true);
					assert_true (properties.get_boolean ("ExtraBoolFalse") == false);

					var extra_data = properties.get_bytes ("ExtraData");
					assert_true (extra_data.length == 3);
					assert_true (extra_data[0] == 0x01);
					assert_true (extra_data[1] == 0x02);
					assert_true (extra_data[2] == 0x03);

					var extra_strings = properties.get_array ("ExtraStrings");
					assert_true (extra_strings.length == 2);
					assert_true (extra_strings.get_string (0) == "A");
					assert_true (extra_strings.get_string (1) == "B");
				} catch (Frida.Fruity.PlistError e) {
					printerr ("%s\n", e.message);
					assert_not_reached ();
				}
			}

			private static void to_xml_yields_complete_document () {
				var plist = new Frida.Fruity.Plist ();
				plist.set_string ("MessageType", "Detached");
				plist.set_integer ("DeviceID", 2);

				var properties = new Frida.Fruity.PlistDict ();
				properties.set_string ("ConnectionType", "USB");
				properties.set_integer ("DeviceID", 2);
				properties.set_boolean ("ExtraBoolTrue", true);
				properties.set_boolean ("ExtraBoolFalse", false);
				properties.set_bytes ("ExtraData", new Bytes ({ 0x01, 0x02, 0x03 }));
				var extra_strings = new Frida.Fruity.PlistArray ();
				extra_strings.add_string ("A");
				extra_strings.add_string ("B");
				properties.set_array ("ExtraStrings", extra_strings);
				plist.set_dict ("Properties", properties);

				var actual_xml = plist.to_xml ();
				var expected_xml =
					"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
					"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
					"<plist version=\"1.0\">\n" +
					"<dict>\n" +
					"	<key>DeviceID</key>\n" +
					"	<integer>2</integer>\n" +
					"	<key>MessageType</key>\n" +
					"	<string>Detached</string>\n" +
					"	<key>Properties</key>\n" +
					"	<dict>\n" +
					"		<key>ConnectionType</key>\n" +
					"		<string>USB</string>\n" +
					"		<key>DeviceID</key>\n" +
					"		<integer>2</integer>\n" +
					"		<key>ExtraBoolFalse</key>\n" +
					"		<false/>\n" +
					"		<key>ExtraBoolTrue</key>\n" +
					"		<true/>\n" +
					"		<key>ExtraData</key>\n" +
					"		<data>AQID</data>\n" +
					"		<key>ExtraStrings</key>\n" +
					"		<array>\n" +
					"			<string>A</string>\n" +
					"			<string>B</string>\n" +
					"		</array>\n" +
					"	</dict>\n" +
					"</dict>\n" +
					"</plist>\n";
				assert_true (actual_xml == expected_xml);
			}

		}

	}
#endif // HAVE_FRUITY_BACKEND

#if HAVE_DROIDY_BACKEND
	namespace Droidy {

		private static async void backend (Harness h) {
			if (!GLib.Test.slow ()) {
				stdout.printf ("<skipping, run in slow mode with Android device connected> ");
				h.done ();
				return;
			}

			var backend = new DroidyHostSessionBackend ();

			var prov = yield h.setup_remote_backend (backend);

			assert_true (prov.name != "Android Device");

			Variant? icon = prov.icon;
			assert_nonnull (icon);
			var dict = new VariantDict (icon);
			int64 width, height;
			assert_true (dict.lookup ("width", "x", out width));
			assert_true (dict.lookup ("height", "x", out height));
			assert_true (width == 16);
			assert_true (height == 16);
			VariantIter image;
			assert_true (dict.lookup ("image", "ay", out image));
			assert_true (image.n_children () == width * height * 4);

			try {
				Cancellable? cancellable = null;

				var session = yield prov.create (null, cancellable);
				var processes = yield session.enumerate_processes (make_parameters_dict (), cancellable);
				assert_true (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void injector (Harness h) {
			if (!GLib.Test.slow ()) {
				stdout.printf ("<skipping, run in slow mode with Android device connected> ");
				h.done ();
				return;
			}

			string device_serial = "<device-serial>";
			string debuggable_app = "<app-id>";
			string gadget_path = "/path/to/frida-gadget-arm64.so";
			Cancellable? cancellable = null;

			try {
				var gadget_file = File.new_for_path (gadget_path);
				InputStream gadget = yield gadget_file.read_async (Priority.DEFAULT, cancellable);

				var details = yield Frida.Droidy.Injector.inject (gadget, debuggable_app, device_serial, cancellable);

				printerr ("inject() => %p\n", details);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
			}

			h.done ();
		}
	}
#endif // HAVE_DROIDY_BACKEND

#if HAVE_LOCAL_BACKEND
	private static string parse_string_message_payload (string json) {
		Json.Object message;
		try {
			message = Json.from_string (json).get_object ();
		} catch (GLib.Error e) {
			assert_not_reached ();
		}

		assert_true (message.get_string_member ("type") == "send");

		return message.get_string_member ("payload");
	}
#endif

	public class Harness : Frida.Test.AsyncHarness, AgentMessageSink {
		public signal void message_from_script (AgentScriptId script_id, string message, Bytes? data);

		public HostSessionService service {
			get;
			private set;
		}

		private uint timeout = 90;

		private Gee.ArrayList<HostSessionProvider> available_providers = new Gee.ArrayList<HostSessionProvider> ();

		public Harness (owned Frida.Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}

		public Harness.without_timeout (owned Frida.Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
			timeout = 0;
		}

		construct {
			service = new HostSessionService ();
			service.provider_available.connect ((provider) => {
				assert_true (available_providers.add (provider));
			});
			service.provider_unavailable.connect ((provider) => {
				assert_true (available_providers.remove (provider));
			});
		}

		protected override uint provide_timeout () {
			return timeout;
		}

		public async HostSessionProvider setup_local_backend (HostSessionBackend backend) {
			yield add_backend_and_start (backend);

			yield process_events ();
			assert_n_providers_available (1);

			return first_provider ();
		}

		public async HostSessionProvider setup_remote_backend (HostSessionBackend backend) {
			yield add_backend_and_start (backend);

			disable_timeout ();
			yield wait_for_provider ();

			return first_provider ();
		}

		private async void add_backend_and_start (HostSessionBackend backend) {
			service.add_backend (backend);

			try {
				yield service.start ();
			} catch (IOError e) {
				assert_not_reached ();
			}
		}

		public async void teardown_backend (HostSessionBackend backend) {
			try {
				yield service.stop ();
			} catch (IOError e) {
				assert_not_reached ();
			}

			service.remove_backend (backend);
		}

		public async void wait_for_provider () {
			while (available_providers.is_empty) {
				yield process_events ();
			}
		}

		public void assert_no_providers_available () {
			assert_true (available_providers.is_empty);
		}

		public void assert_n_providers_available (int n) {
			assert_true (available_providers.size == n);
		}

		public HostSessionProvider first_provider () {
			assert_true (available_providers.size >= 1);
			return available_providers[0];
		}

		public async char prompt_for_key (string message) {
			char key = 0;

			var done = false;

			new Thread<bool> ("input-worker", () => {
				stdout.printf ("%s", message);
				stdout.flush ();

				key = (char) stdin.getc ();

				Idle.add (() => {
					done = true;
					return false;
				});

				return true;
			});

			while (!done)
				yield process_events ();

			return key;
		}

		protected async void post_messages (AgentMessage[] messages, uint batch_id,
				Cancellable? cancellable) throws Error, IOError {
			foreach (var m in messages) {
				message_from_script (m.script_id, m.text, m.has_data ? new Bytes (m.data) : null);
			}
		}
	}
}
```