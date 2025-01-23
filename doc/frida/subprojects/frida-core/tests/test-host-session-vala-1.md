Response:
### 功能归纳

`test-host-session.vala` 是 Frida 动态插桩工具的核心测试文件之一，主要用于测试 Frida 的会话管理、进程注入、脚本执行、消息传递等功能。以下是该文件的主要功能归纳：

1. **会话管理**：
   - 测试 Frida 如何与目标进程建立会话（`session`），并处理会话的附加（`attach`）和分离（`detach`）操作。
   - 测试会话的生命周期管理，包括会话的创建、销毁、以及会话状态的变化（如进程终止时的会话分离）。

2. **进程注入与脚本执行**：
   - 测试 Frida 如何将脚本注入到目标进程中，并执行脚本代码。
   - 测试脚本与目标进程之间的消息传递机制，确保脚本能够正确发送和接收消息。

3. **消息传递与事件处理**：
   - 测试 Frida 如何处理脚本发送的消息，并将其传递给测试框架进行处理。
   - 测试会话的 `detached` 事件处理，确保在会话分离时能够正确触发回调函数。

4. **进程控制**：
   - 测试 Frida 如何控制目标进程的生命周期，包括进程的启动（`spawn`）、恢复（`resume`）、终止（`kill`）等操作。
   - 测试进程的标准输入输出（`stdio`）处理，确保能够正确捕获进程的输出。

5. **异常处理**：
   - 测试 Frida 如何处理目标进程中的异常情况，如进程崩溃、异常退出等。
   - 测试 Frida 在目标进程异常退出时，如何正确清理资源并触发相应的回调。

6. **跨平台支持**：
   - 测试 Frida 在不同操作系统（如 Linux、macOS）上的行为，确保其在不同平台上的兼容性。
   - 测试 Frida 在 Android 设备上的行为，确保其能够正确注入到 Android 应用中并执行脚本。

### 二进制底层与 Linux 内核相关

在 Linux 环境下，Frida 通过 `ptrace` 系统调用与目标进程进行交互，`ptrace` 是 Linux 内核提供的一个系统调用，允许一个进程（如 Frida）监视和控制另一个进程的执行。Frida 使用 `ptrace` 来实现进程注入、内存读写、寄存器修改等操作。

例如，在 `test-host-session.vala` 中，Frida 通过 `ptrace` 将脚本注入到目标进程中，并监控目标进程的执行状态。如果目标进程崩溃或异常退出，Frida 会通过 `ptrace` 捕获这些事件，并触发相应的回调函数。

### LLDB 调试示例

假设我们想要使用 LLDB 来复现 Frida 的调试功能，以下是一个简单的 LLDB Python 脚本示例，用于附加到目标进程并执行一些基本的调试操作：

```python
import lldb

def attach_to_process(pid):
    # 创建调试器实例
    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(True)
    
    # 附加到目标进程
    target = debugger.CreateTarget("")
    error = lldb.SBError()
    process = target.AttachToProcessWithID(debugger.GetListener(), pid, error)
    
    if error.Success():
        print(f"成功附加到进程 {pid}")
    else:
        print(f"附加失败: {error}")
        return
    
    # 设置断点并继续执行
    breakpoint = target.BreakpointCreateByName("sleep", target.GetExecutable().GetFilename())
    process.Continue()
    
    # 等待进程停止
    listener = debugger.GetListener()
    event = lldb.SBEvent()
    while True:
        if listener.WaitForEvent(1, event):
            if lldb.SBProcess.GetStateFromEvent(event) == lldb.eStateStopped:
                print("进程已停止")
                break
    
    # 打印寄存器信息
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()
    registers = frame.GetRegisters()
    for regs in registers:
        print(f"寄存器组: {regs.GetName()}")
        for reg in regs:
            print(f"{reg.GetName()} = {reg.GetValue()}")
    
    # 分离进程
    process.Detach()

if __name__ == "__main__":
    pid = 1234  # 替换为目标进程的 PID
    attach_to_process(pid)
```

### 逻辑推理与假设输入输出

假设我们有一个目标进程，其 PID 为 `1234`，并且该进程中有一个名为 `sleep` 的函数。我们使用上述 LLDB 脚本附加到该进程，并在 `sleep` 函数处设置断点。

- **输入**：目标进程的 PID 为 `1234`。
- **输出**：
  - 成功附加到进程 `1234`。
  - 进程在 `sleep` 函数处停止。
  - 打印出当前线程的寄存器信息。
  - 最后分离进程。

### 用户常见错误

1. **权限不足**：
   - 用户可能没有足够的权限附加到目标进程。例如，在 Linux 上，普通用户无法附加到其他用户的进程。解决方案是以 `root` 用户运行调试器。

2. **目标进程不存在**：
   - 用户可能提供了错误的 PID，导致调试器无法找到目标进程。解决方案是确保提供的 PID 是正确的。

3. **断点设置失败**：
   - 如果目标进程中没有名为 `sleep` 的函数，断点设置将失败。解决方案是确保目标进程中有该函数，或者设置其他有效的断点。

### 用户操作步骤

1. **启动目标进程**：
   - 用户首先启动一个目标进程，例如一个简单的 C 程序，其中包含 `sleep` 函数。

2. **获取目标进程的 PID**：
   - 用户使用 `ps` 或 `top` 命令获取目标进程的 PID。

3. **运行 LLDB 脚本**：
   - 用户运行上述 LLDB Python 脚本，并传入目标进程的 PID。

4. **观察调试输出**：
   - 用户观察调试器的输出，确保进程成功附加并在 `sleep` 函数处停止。

5. **分离进程**：
   - 用户确认调试完成后，调试器会自动分离进程。

通过这些步骤，用户可以复现 Frida 的部分调试功能，并理解 Frida 如何与目标进程进行交互。
### 提示词
```
这是目录为frida/subprojects/frida-core/tests/test-host-session.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
;
				var session = yield device.attach (process.id, options);
				var detached_handler = session.detached.connect ((reason, crash) => {
					if (reason == CONNECTION_TERMINATED) {
						seen_detaches++;
						Idle.add (() => {
							session.resume.begin ();
							return false;
						});
					} else {
						assert (reason == APPLICATION_REQUESTED);
					}
				});

				DBusConnection? peer_connection = null;
				uint filter_id = 0;
				if (strategy == PEER) {
					yield session.setup_peer_connection ();

					peer_connection = session._get_connection ();
					bool disrupting = false;
					var main_context = MainContext.ref_thread_default ();
					filter_id = peer_connection.add_filter ((conn, message, incoming) => {
						if (disrupting)
							return null;

						var direction = incoming ? ChaosProxy.Direction.IN : ChaosProxy.Direction.OUT;

						switch (proxy.on_message (message, direction)) {
							case FORWARD:
								break;
							case FORWARD_THEN_DISRUPT:
								disrupting = true;
								break;
							case DISRUPT:
								disrupting = true;
								message = null;
								break;
						}

						if (disrupting) {
							var source = new IdleSource ();
							source.set_callback (() => {
								peer_connection.close.begin ();
								return false;
							});
							source.attach (main_context);
						}

						return message;
					});
				}

				var script = yield session.create_script ("""
					recv(onMessage);
					function onMessage(message) {
					  const { serial, count } = message;
					  for (let i = 0; i !== count; i++) {
					    send({ id: serial + i });
					  }
					  recv(onMessage);
					}
					""");
				var message_handler = script.message.connect ((json, data) => {
					var parser = new Json.Parser ();
					try {
						parser.load_from_data (json);
					} catch (GLib.Error e) {
						assert_not_reached ();
					}

					var reader = new Json.Reader (parser.get_root ());

					assert (reader.read_member ("type") && reader.get_string_value () == "send");
					reader.end_member ();

					assert (reader.read_member ("payload") && reader.read_member ("id"));
					int64 id = reader.get_int_value ();

					if (messages_summary.len != 0)
						messages_summary.append_c (',');
					messages_summary.append (id.to_string ());
					seen_messages++;

					if (waiting)
						run_reliability_scenario.callback ();
				});
				yield script.load ();

				script.post ("""{"serial":10,"count":3}""");

				while (seen_messages < 3) {
					waiting = true;
					yield;
					waiting = false;
				}

				// In case some unexpected messages show up...
				Timeout.add (100, run_reliability_scenario.callback);
				yield;

				seen_disruptions = seen_detaches;
				assert (seen_messages == 3);
				assert (messages_summary.str == "10,11,12");

				script.disconnect (message_handler);
				if (peer_connection != null)
					peer_connection.remove_filter (filter_id);
				session.disconnect (detached_handler);

				yield device_manager.close ();
				proxy.close ();
				yield control_service.stop ();
			} catch (GLib.Error e) {
				printerr ("Oops: %s\n", e.message);
				assert_not_reached ();
			}

			h.done ();
		}

		private class ChaosProxy : Object {
			public uint16 proxy_port {
				get {
					return _proxy_port;
				}
			}

			public uint16 target_port {
				get;
				construct;
			}

			public Inducer on_message;

			private WebService service;
			private uint16 _proxy_port;
			private SocketAddress target_address;
			private Gee.Set<Cancellable> cancellables = new Gee.HashSet<Cancellable> ();

			public delegate Action Inducer (DBusMessage message, Direction direction);

			public enum Action {
				FORWARD,
				FORWARD_THEN_DISRUPT,
				DISRUPT,
			}

			public enum Direction {
				IN,
				OUT
			}

			public ChaosProxy (uint16 target_port, owned Inducer on_message) {
				Object (target_port: target_port);

				this.on_message = (owned) on_message;
			}

			construct {
				service = new WebService (new EndpointParameters ("127.0.0.1", 1337), CONTROL,
					PortConflictBehavior.PICK_NEXT);
				service.incoming.connect (on_incoming_connection);

				target_address = new InetSocketAddress.from_string ("127.0.0.1", target_port);
			}

			public async void start () {
				try {
					yield service.start (null);
				} catch (GLib.Error e) {
					assert_not_reached ();
				}

				_proxy_port = (uint16) ((InetSocketAddress) service.listen_address).port;
			}

			public void close () {
				foreach (var cancellable in cancellables)
					cancellable.cancel ();
				cancellables.clear ();

				service.stop ();
			}

			private void on_incoming_connection (IOStream proxy_connection, SocketAddress remote_address) {
				handle_incoming_connection.begin (proxy_connection);
			}

			private async void handle_incoming_connection (IOStream proxy_connection) throws GLib.Error {
				var cancellable = new Cancellable ();
				cancellables.add (cancellable);

				IOStream? target_stream = null;
				try {
					var client = new SocketClient ();
					SocketConnection target_connection = yield client.connect_async (target_address, cancellable);
					Tcp.enable_nodelay (target_connection.socket);
					target_stream = target_connection;

					WebServiceTransport transport = PLAIN;
					string? origin = null;

					target_stream = yield negotiate_connection (target_stream, transport, "lolcathost", origin,
						cancellable);

					handle_io.begin (Direction.OUT, proxy_connection.input_stream, target_stream.output_stream,
						cancellable);
					yield handle_io (Direction.IN, target_stream.input_stream, proxy_connection.output_stream,
						cancellable);
				} finally {
					cancellable.cancel ();
					cancellables.remove (cancellable);

					Idle.add (() => {
						if (target_stream != null)
							target_stream.close_async.begin ();
						proxy_connection.close_async.begin ();
						return false;
					});
				}
			}

			private async void handle_io (Direction direction, InputStream raw_input, OutputStream output,
					Cancellable cancellable) throws GLib.Error {
				var input = new BufferedInputStream (raw_input);

				ssize_t header_size = 16;
				int io_priority = Priority.DEFAULT;

				while (true) {
					ssize_t available = (ssize_t) input.get_available ();

					if (available < header_size) {
						available = yield input.fill_async (header_size - available, io_priority, cancellable);
						if (available < header_size)
							break;
					}

					ssize_t needed = DBusMessage.bytes_needed (input.peek_buffer ());

					ssize_t missing = needed - available;
					if (missing > 0)
						available = yield input.fill_async (missing, io_priority, cancellable);

					var blob = input.read_bytes (needed);
					unowned uint8[] data = blob.get_data ();

					var message = new DBusMessage.from_blob (data, DBusCapabilityFlags.NONE);

					Action action = on_message (message, direction);

					if (action == DISRUPT) {
						cancellable.cancel ();
						break;
					}

					size_t bytes_written;
					yield output.write_all_async (data, io_priority, cancellable, out bytes_written);

					if (action == FORWARD_THEN_DISRUPT) {
						cancellable.cancel ();
						break;
					}
				}
			}
		}

		private static async void latency_should_be_nominal (Harness h, Strategy strategy) {
			h.disable_timeout ();

			try {
				ControlService control_service;
				uint16 control_port = 27042;
				while (true) {
					var ep = new EndpointParameters ("127.0.0.1", control_port);
					control_service = new ControlService (ep);
					try {
						yield control_service.start ();
						break;
					} catch (Error e) {
						if (e is Error.ADDRESS_IN_USE) {
							control_port++;
							continue;
						}
						throw e;
					}
				}

				var device_manager = new DeviceManager ();
				var device = yield device_manager.add_remote_device ("127.0.0.1:%u".printf (control_port));

				yield measure_latency (h, device, strategy);

				yield device_manager.close ();
				yield control_service.stop ();
			} catch (GLib.Error e) {
				printerr ("Oops: %s\n", e.message);
				assert_not_reached ();
			}

			h.done ();
		}
#endif // HAVE_SOCKET_BACKEND

		private async void measure_latency (Harness h, Device device, Strategy strategy) throws GLib.Error {
			h.disable_timeout ();

			var process = Frida.Test.Process.create (Frida.Test.Labrats.path_to_executable ("sleeper"));

			var session = yield device.attach (process.id);

			if (strategy == PEER)
				yield session.setup_peer_connection ();

			var script = yield session.create_script ("""
				recv('ping', onPing);
				function onPing(message) {
				  send({ type: 'pong' });
				  recv('ping', onPing);
				}
				""");
			var message_handler = script.message.connect ((json, data) => {
				var parser = new Json.Parser ();
				try {
					parser.load_from_data (json);
				} catch (GLib.Error e) {
					assert_not_reached ();
				}

				var reader = new Json.Reader (parser.get_root ());

				assert (reader.read_member ("type") && reader.get_string_value () == "send");
				reader.end_member ();

				assert (reader.read_member ("payload") && reader.read_member ("type") && reader.get_string_value () == "pong");
				reader.end_member ();

				measure_latency.callback ();
			});
			try {
				yield script.load ();

				var timer = new Timer ();
				for (int i = 0; i != 100; i++) {
					timer.reset ();
					script.post ("""{"type":"ping"}""");
					yield;
					printerr (" [%d: %u ms]", i + 1, (uint) (timer.elapsed () * 1000.0));

					Idle.add (measure_latency.callback);
					yield;

					if ((i + 1) % 10 == 0) {
						printerr ("\n");
						if (GLib.Test.verbose ())
							yield h.prompt_for_key ("Hit a key to do 10 more: ");
					}
				}
			} finally {
				script.disconnect (message_handler);
			}

			yield script.unload ();

			yield session.detach ();
		}

	}

#if LINUX
	namespace Linux {

		private static async void backend (Harness h) {
			var backend = new LinuxHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			assert_true (prov.name == "Local System");

			try {
				Cancellable? cancellable = null;

				var session = yield prov.create (null, cancellable);

				var applications = yield session.enumerate_applications (make_parameters_dict (), cancellable);
				var processes = yield session.enumerate_processes (make_parameters_dict (), cancellable);
				assert_true (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var app in applications)
						stdout.printf ("identifier='%s' name='%s'\n", app.identifier, app.name);

					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				printerr ("ERROR: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void spawn (Harness h) {
			if ((Frida.Test.os () == Frida.Test.OS.ANDROID || Frida.Test.os_arch_suffix () == "-linux-arm") &&
					!GLib.Test.slow ()) {
				stdout.printf ("<skipping, run in slow mode> ");
				h.done ();
				return;
			}

			var backend = new LinuxHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			try {
				Cancellable? cancellable = null;

				var host_session = yield prov.create (null, cancellable);

				uint pid = 0;
				bool waiting = false;

				string received_output = null;
				var output_handler = host_session.output.connect ((source_pid, fd, data) => {
					assert_true (source_pid == pid);
					assert_true (fd == 1);

					var buf = new uint8[data.length + 1];
					Memory.copy (buf, data, data.length);
					buf[data.length] = '\0';
					char * chars = buf;
					received_output = (string) chars;

					if (waiting)
						spawn.callback ();
				});

				var options = HostSpawnOptions ();
				options.stdio = PIPE;
				pid = yield host_session.spawn (Frida.Test.Labrats.path_to_executable ("sleeper"), options, cancellable);

				var session_id = yield host_session.attach (pid, make_parameters_dict (), cancellable);
				var session = yield prov.link_agent_session (host_session, session_id, h, cancellable);

				string received_message = null;
				var message_handler = h.message_from_script.connect ((script_id, message, data) => {
					received_message = message;
					if (waiting)
						spawn.callback ();
				});

				var script_id = yield session.create_script ("""
					var write = new NativeFunction(Module.getExportByName(null, 'write'), 'int', ['int', 'pointer', 'int']);
					var message = Memory.allocUtf8String('Hello stdout');
					write(1, message, 12);
					for (const m of Process.enumerateModules()) {
					  if (m.name.startsWith('libc')) {
					    Interceptor.attach (Module.getExportByName(m.name, 'sleep'), {
					      onEnter(args) {
					        send({ seconds: args[0].toInt32() });
					      }
					    });
					    break;
					  }
					}
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
				assert_true (received_message == "{\"type\":\"send\",\"payload\":{\"seconds\":60}}");
				h.disconnect (message_handler);

				yield host_session.kill (pid, cancellable);
			} catch (GLib.Error e) {
				printerr ("Unexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void fork (Harness h) {
			yield Unix.run_fork_scenario (h, Frida.Test.Labrats.path_to_executable ("forker"));
		}

		private static async void fork_plus_exec (Harness h, string method) {
			yield Unix.run_fork_plus_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), method);
		}

		private static async void bad_exec (Harness h) {
			yield Unix.run_bad_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), "execv");
		}

		private static async void bad_then_good_exec (Harness h) {
			yield Unix.run_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), "spawn-bad-then-good-path", "execv");
		}

		namespace Manual {

			private static async void spawn_android_app (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode on Android device> ");
					h.done ();
					return;
				}

				h.disable_timeout (); /* this is a manual test after all */

				try {
					var device_manager = new DeviceManager ();
					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

					string package_name = "com.android.settings";
					string? activity_name = ".SecuritySettings";
					string received_message = null;
					bool waiting = false;

					var options = new SpawnOptions ();
					if (activity_name != null)
						options.aux["activity"] = new Variant.string (activity_name);

					printerr ("device.spawn(\"%s\")\n", package_name);
					var pid = yield device.spawn (package_name, options);

					printerr ("device.attach(%u)\n", pid);
					var session = yield device.attach (pid);

					printerr ("session.create_script()\n");
					var script = yield session.create_script ("""
						Java.perform(() => {
						  const Activity = Java.use('android.app.Activity');
						  Activity.onResume.implementation = function () {
						    send('onResume');
						    this.onResume();
						  };
						});
						""");
					script.message.connect ((message, data) => {
						received_message = message;
						if (waiting)
							spawn_android_app.callback ();
					});

					printerr ("script.load()\n");
					yield script.load ();

					printerr ("device.resume(%u)\n", pid);
					yield device.resume (pid);

					printerr ("await_message()\n");
					while (received_message == null) {
						waiting = true;
						yield;
						waiting = false;
					}
					printerr ("received_message: %s\n", received_message);
					assert_true (received_message == "{\"type\":\"send\",\"payload\":\"onResume\"}");
					received_message = null;

					yield device_manager.close ();

					h.done ();
				} catch (GLib.Error e) {
					printerr ("ERROR: %s\n", e.message);
					assert_not_reached ();
				}
			}

		}

	}
#endif

#if DARWIN
	namespace Darwin {

		private static async void backend (Harness h) {
			var backend = new DarwinHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			assert_true (prov.name == "Local System");

			if (Frida.Test.os () == Frida.Test.OS.MACOS) {
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
			}

			try {
				Cancellable? cancellable = null;

				var session = yield prov.create (null, cancellable);

				var applications = yield session.enumerate_applications (make_parameters_dict (), cancellable);
				var processes = yield session.enumerate_processes (make_parameters_dict (), cancellable);
				assert_true (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var app in applications)
						stdout.printf ("identifier='%s' name='%s'\n", app.identifier, app.name);

					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void spawn_native (Harness h) {
			yield run_spawn_scenario (h, target_name_of_native ("sleeper"));
		}

		private static async void spawn_other (Harness h) {
			yield run_spawn_scenario (h, target_name_of_other ("sleeper"));
		}

		private static async void run_spawn_scenario (Harness h, string target_name) {
			var backend = new DarwinHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			try {
				Cancellable? cancellable = null;

				var host_session = yield prov.create (null, cancellable);

				uint pid = 0;
				bool waiting = false;

				string received_output = null;
				var output_handler = host_session.output.connect ((source_pid, fd, data) => {
					assert_true (source_pid == pid);
					assert_true (fd == 1);

					var buf = new uint8[data.length + 1];
					Memory.copy (buf, data, data.length);
					buf[data.length] = '\0';
					char * chars = buf;
					received_output = (string) chars;

					if (waiting)
						run_spawn_scenario.callback ();
				});

				var options = HostSpawnOptions ();
				options.stdio = PIPE;
				pid = yield host_session.spawn (Frida.Test.Labrats.path_to_file (target_name), options, cancellable);

				var session_id = yield host_session.attach (pid, make_parameters_dict (), cancellable);
				var session = yield prov.link_agent_session (host_session, session_id, h, cancellable);

				string received_message = null;
				var message_handler = h.message_from_script.connect ((script_id, message, data) => {
					received_message = message;
					if (waiting)
						run_spawn_scenario.callback ();
				});

				var script_id = yield session.create_script ("""
					const write = new NativeFunction(Module.getExportByName('libSystem.B.dylib', 'write'), 'int', ['int', 'pointer', 'int']);
					const message = Memory.allocUtf8String('Hello stdout');
					const cout = Module.getExportByName('libc++.1.dylib', '_ZNSt3__14coutE').readPointer();
					const properlyInitialized = !cout.isNull();
					write(1, message, 12);
					const getMainPtr = Module.findExportByName(null, 'CFRunLoopGetMain');
					if (getMainPtr !== null) {
					  const getMain = new NativeFunction(getMainPtr, 'pointer', []);
					  getMain();
					}
					const sleepFuncName = (Process.arch === 'ia32') ? 'sleep$UNIX2003' : 'sleep';
					Interceptor.attach(Module.getExportByName('libSystem.B.dylib', sleepFuncName), {
					  onEnter(args) {
					    send({ seconds: args[0].toInt32(), initialized: properlyInitialized });
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
#if MACOS
				// FIXME: Improve early instrumentation on Monterey
				assert_true (received_message.has_prefix ("{\"type\":\"send\",\"payload\":{\"seconds\":60,\"initialized\":"));
#else
				assert_true (received_message == "{\"type\":\"send\",\"payload\":{\"seconds\":60,\"initialized\":true}}");
#endif
				h.disconnect (message_handler);

				yield host_session.kill (pid, cancellable);
			} catch (GLib.Error e) {
				printerr ("Unexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void spawn_without_attach_native (Harness h) {
			yield run_spawn_scenario_with_stdio (h, target_name_of_native ("stdio-writer"));
		}

		private static async void spawn_without_attach_other (Harness h) {
			yield run_spawn_scenario_with_stdio (h, target_name_of_other ("stdio-writer"));
		}

		private static async void run_spawn_scenario_with_stdio (Harness h, string target_name) {
			var backend = new DarwinHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			try {
				Cancellable? cancellable = null;

				var host_session = yield prov.create (null, cancellable);

				uint pid = 0;
				bool waiting = false;

				string received_stdout = null;
				string received_stderr = null;
				var output_handler = host_session.output.connect ((source_pid, fd, data) => {
					assert_true (source_pid == pid);

					if (data.length > 0) {
						var buf = new uint8[data.length + 1];
						Memory.copy (buf, data, data.length);
						buf[data.length] = '\0';
						char * chars = buf;
						var received_output = (string) chars;

						if (fd == 1)
							received_stdout = received_output;
						else if (fd == 2)
							received_stderr = received_output;
						else
							assert_not_reached ();
					} else {
						if (fd == 1)
							assert_nonnull (received_stdout);
						else if (fd == 2)
							assert_nonnull (received_stderr);
						else
							assert_not_reached ();
					}

					if (waiting)
						run_spawn_scenario_with_stdio.callback ();
				});

				var options = HostSpawnOptions ();
				options.stdio = PIPE;
				pid = yield host_session.spawn (Frida.Test.Labrats.path_to_file (target_name), options, cancellable);

				yield host_session.resume (pid, cancellable);

				while (received_stdout == null || received_stderr == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (received_stdout == "Hello stdout");
				assert_true (received_stderr == "Hello stderr");
				host_session.disconnect (output_handler);

				yield host_session.kill (pid, cancellable);
			} catch (GLib.Error e) {
				printerr ("Unexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void own_memory_ranges_should_be_cloaked (Harness h) {
			if (Frida.Test.os () != Frida.Test.OS.MACOS || Frida.Test.cpu () != Frida.Test.CPU.X86_64) {
				stdout.printf ("<skipping, test only available on macOS/x86_64 for now> ");
				h.done ();
				return;
			}

			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);
				var process = Frida.Test.Process.start (Frida.Test.Labrats.path_to_executable ("sleeper"));

				/* TODO: improve injector to handle injection into a process that hasn't yet finished initializing */
				Thread.usleep (50000);

				/* Warm up static allocations */
				var session = yield device.attach (process.id);
				yield session.detach ();
				session = null;

				/* The injector does cleanup 50ms after detecting that the remote thread is dead */
				Timeout.add (100, own_memory_ranges_should_be_cloaked.callback);
				yield;

				var original_ranges = dump_ranges (process.id);

				session = yield device.attach (process.id);
				var script = yield session.create_script ("""
					const ranges = Process.enumerateRanges({ protection: '---', coalesce: true })
					    .map(range => `${range.base.toString()}-${range.base.add(range.size).toString()}`);
					send(ranges);
					""");
				string received_message = null;
				bool waiting = false;
				script.message.connect ((message, data) => {
					assert_null (received_message);
					received_message = message;
					if (waiting)
						own_memory_ranges_should_be_cloaked.callback ();
				});

				yield script.load ();

				if (received_message == null) {
					waiting = true;
					yield;
					waiting = false;
				}

				var message = Json.from_string (received_message).get_object ();
				assert_true (message.get_string_member ("type") == "send");

				var uncloaked_ranges = new Gee.ArrayList<string> ();
				message.get_array_member ("payload").foreach_element ((array, index, element) => {
					var range = element.get_string ();
					if (!original_ranges.contains (range)) {
						uncloaked_ranges.add (range);
					}
				});

				if (!uncloaked_ranges.is_empty) {
					printerr ("\n\nUH-OH, uncloaked_ranges.size=%d:\n", uncloaked_ranges.size);
					foreach (var range in uncloaked_ranges) {
						printerr ("\t%s\n", range);
					}
				}
				printerr ("\n");

				// assert_true (uncloaked_ranges.is_empty);

				yield script.unload ();

				yield device_manager.close ();

				h.done ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		private Gee.HashSet<string> dump_ranges (uint pid) {
			var ranges = new Gee.ArrayList<Range> ();
			var range_by_end_address = new Gee.HashMap<string, Range> ();

			try {
				string vmmap_output;
				GLib.Process.spawn_sync (null, new string[] { "/usr/bin/vmmap", "-interleaved", "%u".printf (pid) }, null, 0, null, out vmmap_output, null, null);

				var range_pattern = new Regex ("([0-9a-f]{8,})-([0-9a-f]{8,})\\s+.+\\s+([rwx-]{3})\\/");
				MatchInfo match_info;
				assert_true (range_pattern.match (vmmap_output, 0, out match_info));
				while (match_info.matches ()) {
					var start = uint64.parse ("0x" + match_info.fetch (1));
					var end = uint64.parse ("0x" + match_info.fetch (2));
					var protection = match_info.fetch (3);

					var address_format = "0x%" + uint64.FORMAT_MODIFIER + "x";
					var start_str = start.to_string (address_format);
					var end_str = end.to_string (address_format);

					Range range;
					var existing_range = range_by_end_address[start_str];
					if (existing_range != null && existing_range.protection == protection) {
						existing_range.end = end_str;
						range = existing_range;
					} else {
						range = new Range (start_str, end_str, protection);
						ranges.add (range);
					}
					range_by_end_address[end_str] = range;

					match_info.next ();
				}
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			var result = new Gee.HashSet<string> ();
			foreach (var range in ranges)
				result.add ("%s-%s".printf (range.start, range.end));
			return result;
		}

		private class Range {
			public string start;
			public string end;
			public string protection;

			public Range (string start, string end, string protection) {
				this.start = start;
				this.end = end;
				this.protection = protection;
			}
		}

		namespace ExitMonitor {
			private static async void abort_from_js_thread_should_not_deadlock (Harness h) {
				try {
					var device_manager = new DeviceManager ();
					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);
					var process = Frida.Test.Process.start (Frida.Test.Labrats.path_to_executable ("sleeper"));

					/* TODO: improve injector to handle injection into a process that hasn't yet finished initializing */
					Thread.usleep (50000);

					var session = yield device.attach (process.id);
					var script = yield session.create_script ("""
						rpc.exports = {
						  dispose() {
						    send('dispose');
						  }
						};

						const abort = new NativeFunction(Module.getExportByName('/usr/lib/system/libsystem_c.dylib', 'abort'), 'void', [], { exceptions: 'propagate' });
						setTimeout(() => { abort(); }, 50);
						""");

					string? detach_reason = null;
					string? received_message = null;
					bool waiting = false;
					session.detached.connect (reason => {
						detach_reason = reason.to_string ();
						if (waiting)
							abort_from_js_thread_should_not_deadlock.callback ();
					});
					script.message.connect ((message, data) => {
						assert_null (received_message);
						received_message = message;
						if (waiting)
							abort_from_js_thread_should_not_deadlock.callback ();
					});

					yield script.load ();

					while (received_message == null || detach_reason == null) {
						waiting = true;
						yield;
						waiting = false;
					}
					assert_true (received_message == "{\"type\":\"send\",\"payload\":\"dispose\"}");
					assert_true (detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

					h.done ();
				} catch (GLib.Error e) {
					printerr ("ERROR: %s\n", e.message);
				}
			}
		}

		namespace UnwindSitter {
			private static async void exceptions_on_swizzled_objc_methods_should_be_caught (Harness h) {
				try {
					var device_manager = new DeviceManager ();
					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);
					var process = Frida.Test.Process.create (
						Frida.Test.Labrats.path_to_executable ("exception-catcher"));

					/*
					 * TODO: Improve injector to handle injection into a process that hasn't yet finished initializing.
					 */
					Thread.usleep (50000);

					var session = yield device.attach (process.id);
					var script = yield session.create_script ("""
						const meth = ObjC.classes.NSBundle['- initWithURL:'];
						const origImpl = meth.implementation;
						meth.implementation = ObjC.implement(meth, function (handle, selector, url) {
						  return origImpl(handle, selector, NULL);
						});
						Interceptor.attach(Module.getExportByName(null, 'abort'), function () {
						  send('abort');
						  Thread.sleep(1);
						});
						Interceptor.attach(Module.getExportByName(null, '__exit'), function (args) {
						  send(`exit(${args[0].toUInt32()})`);
						  Thread.sleep(1);
						});
						""");

					string? detach_reason = null;
					string? received_message = null;
					bool waiting = false;
					session.detached.connect (reason => {
						detach_reason = reason.to_string ();
						if (waiting)
							exceptions_on_swizzled_objc_methods_should_be_caught.callback ();
					});
					script.message.connect ((message, data) => {
						assert_null (received_message);
						received_message = message;
						if (waiting)
							exceptions_on_swizzled_objc_methods_should_be_caught.callback ();
					});

					yield script.load ();
					yield device.resume (process.id);

					while (received_message == null || detach_reason == null) {
						waiting = true;
						yield;
						waiting = false;
					}
					assert_true (received_message == "{\"type\":\"send\",\"payload\":\"exit(0)\"}");
					assert_true (detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

					h.done ();
				} catch (GLib.Error e) {
					printerr ("ERROR: %s\n", e.message);
				}
			}

			private static async void exceptions_on_intercepted_objc_methods_should_be_caught (Harness h) {
				try {
					var device_manager = new DeviceManager ();
					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);
					var process = Frida.Test.Process.create (
						Frida.Test.Labrats.path_to_executable ("exception-catcher"));

					/*
					 * TODO: Improve injector to handle injection into a process that hasn't yet finished initializing.
					 */
					Thread.usleep (50000);

					var session = yield device.attach (process.id);
					var script = yield session.create_script ("""
						const { NSBundle } = ObjC.classes;
						const meth = NSBundle['+ bundleWithURL:'];
						const methInner = NSBundle['- initWithURL:'];
						Interceptor.attach(meth.implementation, {
						  onEnter(args) {
```