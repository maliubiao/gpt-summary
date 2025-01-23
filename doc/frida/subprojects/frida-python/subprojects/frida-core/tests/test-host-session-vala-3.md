Response:
### 功能归纳

`test-host-session.vala` 是 Frida 动态插桩工具中的一个测试文件，主要用于测试 Frida 的核心功能，特别是与主机会话（Host Session）相关的功能。以下是该文件的主要功能归纳：

1. **测试主机会话的基本功能**：
   - 测试主机会话的创建、连接、断开等基本操作。
   - 测试脚本的加载、执行、消息传递等功能。

2. **测试进程的创建和管理**：
   - 测试通过 Frida 创建新进程（如 `spawner` 进程）并对其进行插桩。
   - 测试子进程的创建、管理和插桩。

3. **测试消息传递和脚本执行**：
   - 测试通过 Frida 脚本与目标进程进行消息传递。
   - 测试脚本的加载、执行以及脚本消息的接收和处理。

4. **测试不同平台的支持**：
   - 测试 Windows 平台下的标准输出和消息拦截功能。
   - 测试 iOS 平台下的 Fruity 后端功能，包括设备连接、应用枚举、进程管理等。
   - 测试 Android 平台下的 Droidy 后端功能，包括设备连接、进程注入等。

5. **测试大消息的处理**：
   - 测试处理大消息的能力，确保 Frida 能够正确处理和传输大尺寸的消息。

6. **测试 Plist 数据的解析和生成**：
   - 测试从 XML 文档构造 Plist 数据，并验证其内容的正确性。
   - 测试将 Plist 数据转换为 XML 文档，并验证生成的 XML 是否符合预期。

### 二进制底层和 Linux 内核相关

- **Windows 平台下的标准输出**：
  - 代码中使用了 `GetStdHandle` 和 `WriteFile` 这两个 Windows API 来获取标准输出句柄并向其写入数据。这是 Windows 平台下的底层操作，直接与操作系统内核交互。
  - 示例代码：
    ```c
    HANDLE stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(stdout, "Hello stdout", 12, NULL, NULL);
    ```

- **消息拦截**：
  - 使用 `Interceptor.attach` 拦截 `GetMessageW` 函数调用，这是 Windows 用户态下的消息处理机制，通常用于 GUI 应用程序的消息循环。
  - 示例代码：
    ```javascript
    Interceptor.attach(Module.getExportByName('user32.dll', 'GetMessageW'), {
      onEnter(args) {
        send('GetMessage');
      }
    });
    ```

### LLDB 调试示例

假设我们想要使用 LLDB 来调试 Frida 的脚本加载和执行过程，以下是一个简单的 LLDB Python 脚本示例，用于在 LLDB 中复现 Frida 的调试功能：

```python
import lldb

def frida_script_load(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 模拟 Frida 脚本加载
    script_id = frame.FindVariable("script_id")
    script_code = frame.FindVariable("script_code")
    
    print(f"Loading script with ID: {script_id.GetValue()}")
    print(f"Script code: {script_code.GetValue()}")

    # 模拟脚本执行
    print("Executing script...")
    # 这里可以添加更多的调试逻辑，比如断点设置、变量监控等

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldb_script.frida_script_load frida_script_load')
    print('The "frida_script_load" LLDB command has been installed.')
```

### 逻辑推理与输入输出

- **假设输入**：
  - 用户通过 Frida 加载一个脚本，脚本内容为 `send('Hello stdout')`。
  - 用户启动一个目标进程，并通过 Frida 对其进行插桩。

- **假设输出**：
  - Frida 成功加载脚本，并向标准输出写入 `Hello stdout`。
  - Frida 成功拦截 `GetMessageW` 函数调用，并发送 `GetMessage` 消息。

### 用户常见错误

1. **脚本加载失败**：
   - 用户可能忘记在脚本中正确调用 `send` 函数，导致消息无法传递。
   - 示例错误代码：
     ```javascript
     // 错误：没有调用 send 函数
     Interceptor.attach(Module.getExportByName('user32.dll', 'GetMessageW'), {
       onEnter(args) {
         // 忘记调用 send
       }
     });
     ```

2. **进程创建失败**：
   - 用户可能提供了错误的目标路径或参数，导致进程创建失败。
   - 示例错误代码：
     ```vala
     var options = new SpawnOptions ();
     options.argv = { "wrong_path", "spawn", "wrong_method" }; // 错误的目标路径和方法
     ```

### 用户操作步骤

1. **启动 Frida 测试**：
   - 用户运行 Frida 测试套件，选择 `test-host-session.vala` 进行测试。

2. **创建进程并加载脚本**：
   - 用户通过 Frida 创建一个新进程，并加载一个脚本进行插桩。

3. **监控输出和消息**：
   - 用户监控标准输出和 Frida 发送的消息，确保脚本正确执行并传递消息。

4. **结束测试**：
   - 用户结束测试，断开与目标进程的连接，并清理资源。

### 总结

`test-host-session.vala` 文件主要测试了 Frida 的核心功能，包括主机会话的管理、进程的创建和插桩、脚本的加载和执行、消息的传递等。通过该测试文件，可以确保 Frida 在不同平台下的功能正常，并且能够正确处理各种边界情况。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/tests/test-host-session.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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