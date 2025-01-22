Response:
### 功能概述

`inject.vala` 是 Frida 动态插桩工具的核心注入模块的一部分，主要负责将 Frida 的脚本注入到目标进程中，并与目标进程进行交互。以下是该文件的主要功能：

1. **命令行参数解析**：
   - 通过 `OptionEntry` 结构体定义了多个命令行选项，如 `--device`、`--file`、`--pid`、`--name`、`--realm`、`--script` 等，用于指定目标设备、进程、脚本路径等。
   - 解析命令行参数并初始化相应的变量。

2. **目标进程的注入**：
   - 根据命令行参数，选择是通过 `spawn` 启动新进程，还是通过 `attach` 附加到现有进程。
   - 使用 `DeviceManager` 获取目标设备，并通过 `Device` 对象与目标进程进行交互。

3. **脚本加载与执行**：
   - 从指定的路径或标准输入读取 JavaScript 脚本。
   - 使用 `ScriptRunner` 类将脚本加载到目标进程中，并处理脚本的输出和输入。

4. **交互模式**：
   - 支持通过标准输入与注入的脚本进行交互，允许用户在运行时向脚本发送数据。
   - 支持脚本的重新加载（热重载），当脚本文件发生变化时自动重新加载。

5. **终端模式管理**：
   - 支持不同的终端模式（`COOKED`、`RAW`、`BINARY`），用于控制脚本与终端的交互方式。
   - 在非 Windows 系统上，通过 `Posix.termios` 管理终端的原始模式和回显设置。

6. **错误处理与日志输出**：
   - 处理脚本执行过程中的错误，并将错误信息输出到标准错误流。
   - 支持脚本通过 `send` 方法向标准输出或标准错误流发送数据。

### 二进制底层与 Linux 内核相关

1. **进程注入**：
   - 通过 `Device.spawn` 和 `Device.attach` 方法，Frida 可以将自身注入到目标进程中。在 Linux 上，这通常涉及 `ptrace` 系统调用，用于控制目标进程的执行流。
   - `ptrace` 是 Linux 内核提供的一个系统调用，允许一个进程（调试器）控制另一个进程（被调试进程）的执行，包括读取和修改寄存器和内存。

2. **终端模式管理**：
   - 在非 Windows 系统上，`Posix.termios` 用于管理终端的输入输出模式。通过 `tcgetattr` 和 `tcsetattr` 系统调用，可以获取和设置终端的属性，如回显、行缓冲等。
   - 例如，`RAW` 模式会禁用终端的行缓冲和回显，允许脚本直接处理用户的输入。

### LLDB 调试示例

假设你想使用 LLDB 调试 `inject.vala` 中的某个功能，比如脚本加载过程。你可以使用以下 LLDB 命令或 Python 脚本来实现：

#### LLDB 命令示例

```bash
# 启动 LLDB 并加载 Frida 的可执行文件
lldb frida-inject

# 设置断点在 ScriptRunner 类的 load 方法
b Frida.Inject.ScriptRunner.load

# 运行程序并传递命令行参数
run --pid 1234 --script /path/to/script.js

# 当程序停在断点时，查看当前栈帧
bt

# 查看 script_path 变量的值
p script_path
```

#### LLDB Python 脚本示例

```python
import lldb

def load_script(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 获取 script_path 变量的值
    script_path = frame.FindVariable("script_path")
    print("Script path: ", script_path.GetSummary())

    # 继续执行
    process.Continue()

# 将 Python 函数注册为 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldb_script.load_script load_script')
```

### 假设输入与输出

#### 输入
- 命令行参数：`--pid 1234 --script /path/to/script.js`
- 目标进程 ID：1234
- 脚本路径：`/path/to/script.js`

#### 输出
- 脚本成功加载到目标进程 1234 中。
- 脚本的输出通过 `send` 方法发送到标准输出或标准错误流。

### 常见使用错误

1. **未指定目标进程或脚本路径**：
   - 错误信息：`PID or name must be specified` 或 `Path to JavaScript file must be specified`
   - 解决方法：确保命令行参数中指定了 `--pid` 或 `--name`，并且提供了有效的脚本路径。

2. **脚本文件不存在或无法读取**：
   - 错误信息：`Failed to reload script: No such file or directory`
   - 解决方法：检查脚本路径是否正确，并确保脚本文件存在且可读。

3. **同时指定 `-e` 和 `-i` 选项**：
   - 错误信息：`Cannot specify both -e and -i options`
   - 解决方法：`-e` 和 `-i` 选项不能同时使用，选择其中一个。

### 用户操作步骤

1. **启动 Frida 注入工具**：
   - 用户通过命令行启动 `frida-inject`，并指定目标进程 ID 或名称，以及要注入的脚本路径。

2. **脚本加载与执行**：
   - Frida 将脚本加载到目标进程中，并开始执行脚本中的逻辑。

3. **交互模式**：
   - 如果启用了交互模式（`-i`），用户可以通过标准输入与脚本进行交互，脚本可以通过 `onFridaStdin` 方法接收输入。

4. **脚本输出**：
   - 脚本的输出通过 `send` 方法发送到标准输出或标准错误流，用户可以在终端中看到这些输出。

5. **错误处理**：
   - 如果脚本执行过程中发生错误，Frida 会将错误信息输出到标准错误流，并终止注入过程。

### 调试线索

1. **命令行参数解析**：
   - 用户通过命令行参数指定目标进程和脚本路径，这些参数会被解析并存储在相应的变量中。

2. **目标进程的注入**：
   - Frida 通过 `DeviceManager` 获取目标设备，并通过 `Device` 对象与目标进程进行交互。用户可以通过调试器观察 `Device.spawn` 或 `Device.attach` 的调用过程。

3. **脚本加载与执行**：
   - 脚本通过 `ScriptRunner` 类加载到目标进程中，用户可以通过调试器观察 `ScriptRunner.load` 方法的执行过程。

4. **交互模式**：
   - 如果启用了交互模式，用户可以通过调试器观察 `watch_stdin` 和 `read_line` 方法的执行过程，了解脚本如何接收用户输入。

5. **错误处理**：
   - 如果脚本执行过程中发生错误，用户可以通过调试器观察 `on_detached` 方法的执行过程，了解错误是如何被捕获和处理的。

通过这些步骤，用户可以逐步跟踪 Frida 注入工具的执行过程，定位和解决问题。
Prompt: 
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/inject/inject.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
namespace Frida.Inject {
	private static Application application;

	private static string? device_id;
	private static string? spawn_file;
	private static int target_pid = -1;
	private static string? target_name;
	private static string? realm_str;
	private static string? script_path;
	private static string? script_runtime_str;
	private static string? parameters_str;
	private static bool eternalize;
	private static bool interactive;
	private static bool enable_development;
	private static bool output_version;

	const OptionEntry[] options = {
		{ "device", 'D', 0, OptionArg.STRING, ref device_id, "connect to device with the given ID", "ID" },
		{ "file", 'f', 0, OptionArg.STRING, ref spawn_file, "spawn FILE", "FILE" },
		{ "pid", 'p', 0, OptionArg.INT, ref target_pid, "attach to PID", "PID" },
		{ "name", 'n', 0, OptionArg.STRING, ref target_name, "attach to NAME", "NAME" },
		{ "realm", 'r', 0, OptionArg.STRING, ref realm_str, "attach in REALM", "REALM" },
		{ "script", 's', 0, OptionArg.FILENAME, ref script_path, null, "JAVASCRIPT_FILENAME" },
		{ "runtime", 'R', 0, OptionArg.STRING, ref script_runtime_str, "Script runtime to use", "qjs|v8" },
		{ "parameters", 'P', 0, OptionArg.STRING, ref parameters_str, "Parameters as JSON, same as Gadget", "PARAMETERS_JSON" },
		{ "eternalize", 'e', 0, OptionArg.NONE, ref eternalize, "Eternalize script and exit", null },
		{ "interactive", 'i', 0, OptionArg.NONE, ref interactive, "Interact with script through stdin", null },
		{ "development", 0, 0, OptionArg.NONE, ref enable_development, "Enable development mode", null },
		{ "version", 0, 0, OptionArg.NONE, ref output_version, "Output version information and exit", null },
		{ null }
	};

	private static int main (string[] args) {
#if !WINDOWS
		Posix.setsid ();
#endif

		Environment.init ();

		try {
			var ctx = new OptionContext ();
			ctx.set_help_enabled (true);
			ctx.add_main_entries (options, null);
			ctx.parse (ref args);

			if (output_version) {
				print ("%s\n", version_string ());
				return 0;
			}
		} catch (OptionError e) {
			printerr ("%s\n", e.message);
			printerr ("Run '%s --help' to see a full list of available command line options.\n", args[0]);
			return 1;
		}

		if (spawn_file == null && target_pid == -1 && target_name == null) {
			printerr ("PID or name must be specified\n");
			return 2;
		}

		var options = new SessionOptions ();

		if (realm_str != null) {
			try {
				options.realm = Realm.from_nick (realm_str);
			} catch (Error e) {
				printerr ("%s\n", e.message);
				return 3;
			}
		}

		if (script_path == null || script_path == "") {
			printerr ("Path to JavaScript file must be specified\n");
			return 4;
		}

		string? script_source = null;
		if (script_path == "-") {
			script_path = null;
			script_source = read_stdin ();
		}

		ScriptRuntime script_runtime = DEFAULT;
		if (script_runtime_str != null) {
			try {
				script_runtime = ScriptRuntime.from_nick (script_runtime_str);
			} catch (Error e) {
				printerr ("%s\n", e.message);
				return 5;
			}
		}

		var parameters = new Json.Node.alloc ().init_object (new Json.Object ());
		if (parameters_str != null) {
			if (parameters_str == "") {
				printerr ("Parameters argument must be specified as JSON if present\n");
				return 6;
			}

			try {
				var root = Json.from_string (parameters_str);
				if (root.get_node_type () != OBJECT) {
					printerr ("Failed to parse parameters argument as JSON: not an object\n");
					return 7;
				}

				parameters.take_object (root.get_object ());
			} catch (GLib.Error e) {
				printerr ("Failed to parse parameters argument as JSON: %s\n", e.message);
				return 8;
			}
		}

		if (interactive && eternalize) {
			printerr ("Cannot specify both -e and -i options\n");
			return 9;
		}

		application = new Application (device_id, spawn_file, target_pid, target_name, options, script_path, script_source,
			script_runtime, parameters, enable_development);

#if !WINDOWS
		Posix.signal (Posix.Signal.INT, (sig) => {
			application.shutdown ();
		});
		Posix.signal (Posix.Signal.TERM, (sig) => {
			application.shutdown ();
		});
#endif

		return application.run ();
	}

	private static string read_stdin () {
		var input = new StringBuilder ();
		var buffer = new char[1024];
		while (!stdin.eof ()) {
			string read_chunk = stdin.gets (buffer);
			if (read_chunk == null)
				break;
			input.append (read_chunk);
		}
		return input.str;
	}

	namespace Environment {
		public extern void init ();
	}

	public class Application : Object {
		public string? device_id {
			get;
			construct;
		}

		public string? spawn_file {
			get;
			construct;
		}

		public int target_pid {
			get;
			construct;
		}

		public string? target_name {
			get;
			construct;
		}

		public SessionOptions? session_options {
			get;
			construct;
		}

		public string? script_path {
			get;
			construct;
		}

		public string? script_source {
			get;
			construct;
		}

		public ScriptRuntime script_runtime {
			get;
			construct;
		}

		public Json.Node parameters {
			get;
			construct;
		}

		public bool enable_development {
			get;
			construct;
		}

		private DeviceManager device_manager;
		private ScriptRunner script_runner;
		private Cancellable io_cancellable = new Cancellable ();
		private Cancellable stop_cancellable;

		private int exit_code;
		private MainLoop loop;

		public Application (string? device_id, string? spawn_file, int target_pid, string? target_name,
				SessionOptions? session_options, string? script_path, string? script_source, ScriptRuntime script_runtime,
				Json.Node parameters, bool enable_development) {
			Object (
				device_id: device_id,
				spawn_file: spawn_file,
				target_pid: target_pid,
				target_name: target_name,
				session_options: session_options,
				script_path: script_path,
				script_source: script_source,
				script_runtime: script_runtime,
				parameters: parameters,
				enable_development: enable_development
			);
		}

		public int run () {
			Idle.add (() => {
				start.begin ();
				return false;
			});

			exit_code = 0;

			loop = new MainLoop ();
			loop.run ();

			return exit_code;
		}

		private async void start () {
			device_manager = new DeviceManager ();

			try {
				Device device;
				if (device_id != null)
					device = yield device_manager.get_device_by_id (device_id, 0, io_cancellable);
				else
					device = yield device_manager.get_device_by_type (DeviceType.LOCAL, 0, io_cancellable);

				uint pid;
				if (spawn_file != null) {
					pid = yield device.spawn (spawn_file, null, io_cancellable);
				} else if (target_name != null) {
					var proc = yield device.get_process_by_name (target_name, null, io_cancellable);
					pid = proc.pid;
				} else {
					pid = (uint) target_pid;
				}

				var session = yield device.attach (pid, session_options, io_cancellable);
				session.detached.connect (on_detached);

				var r = new ScriptRunner (session, script_path, script_source, script_runtime, parameters,
					enable_development, io_cancellable);
				yield r.start ();
				script_runner = r;

				if (interactive)
					watch_stdin ();

				if (spawn_file != null) {
					yield device.resume (pid);
				}

				if (eternalize)
					stop.begin ();
			} catch (GLib.Error e) {
				printerr ("%s\n", e.message);
				exit_code = 4;
				stop.begin ();
				return;
			}
		}

		public void shutdown () {
			Idle.add (() => {
				stop.begin ();
				return false;
			});
		}

		private async void stop () {
			if (stop_cancellable != null) {
				stop_cancellable.cancel ();
				return;
			}
			stop_cancellable = new Cancellable ();

			io_cancellable.cancel ();

			try {
				if (script_runner != null) {
					yield script_runner.stop (stop_cancellable);
					script_runner = null;
				}

				yield device_manager.close (stop_cancellable);
				device_manager = null;
			} catch (IOError e) {
				assert (e is IOError.CANCELLED);
			}

			Idle.add (() => {
				loop.quit ();
				return false;
			});
		}

		private void on_detached (SessionDetachReason reason, Crash? crash) {
			if (reason == APPLICATION_REQUESTED)
				return;

			var message = new StringBuilder ();

			message.append ("\033[0;31m");
			if (crash == null) {
				var nick = reason.to_nick ();
				message.append_c (nick[0].toupper ());
				message.append (nick.substring (1).replace ("-", " "));
			} else {
				message.append_printf ("Process crashed: %s", crash.summary);
			}
			message.append ("\033[0m\n");

			if (crash != null) {
				message.append ("\n***\n");
				message.append (crash.report.strip ());
				message.append ("\n***\n");
			}

			printerr ("%s", message.str);

			shutdown ();
		}

		private void watch_stdin () {
			/**
			 * Support reading from stdin for communications with the injected script.
			 * With the console in its default canonical mode, we will read a line at a
			 * time when the user presses enter and send it to a registered RPC method
			 * in the script as follows. Here, the data parameter is the string typed
			 * by the user including the newline.
			 *
			 * rpc.exports = {
			 *   onFridaStdin(data) {
			 *     ...
			 *   }
			 * };
			 */
			var fd = stdin.fileno ();
#if WINDOWS
			var inchan = new IOChannel.win32_new_fd (fd);
#else
			var inchan = new IOChannel.unix_new (fd);
#endif
			inchan.add_watch (IOCondition.IN, (source, condition) => {
				if (script_runner.terminal_mode == COOKED)
					return read_line (source, condition);
				else
					return read_raw (source, condition);
			});
		}

		private bool read_line (IOChannel source, IOCondition condition) {
			if (condition == IOCondition.HUP)
				return false;

			IOStatus status;
			string line = null;
			try {
				status = source.read_line (out line, null, null);
			} catch (GLib.Error e) {
				return true;
			}

			if (status == IOStatus.EOF) {
				loop.quit ();
				return false;
			}

			script_runner.on_stdin (line, null);

			return true;
		}

#if WINDOWS
		private bool read_raw (IOChannel source, IOCondition condition) {
			return false;
		}
#else
		private bool read_raw (IOChannel source, IOCondition condition) {
			var fd = source.unix_get_fd ();

			uint8 buf[1024];
			ssize_t n = Posix.read (fd, buf, buf.length - 1);
			if (n == -1)
				return true;

			bool eof = n == 0;
			if (eof) {
				loop.quit ();
				return false;
			}

			buf[n] = 0;

			if (script_runner.terminal_mode == TerminalMode.BINARY) {
				var bytes = new Bytes (buf[:n]);
				script_runner.on_stdin ("", bytes);
			} else {
				script_runner.on_stdin ((string) buf, null);
			}

			return true;
		}
#endif
	}

	private class ScriptRunner : Object, RpcPeer {
		public TerminalMode terminal_mode {
			get;
			private set;
			default = COOKED;
		}

		private Session session;
		private Script? script;
		private string? script_path;
		private string? script_source;
		private ScriptRuntime script_runtime;
		private Json.Node parameters;
		private bool enable_development = false;

		private bool load_in_progress = false;
		private GLib.FileMonitor script_monitor;
		private Source script_unchanged_timeout;

		private RpcClient rpc_client;

#if !WINDOWS
		private Posix.termios? original_term;
#endif

		private Cancellable io_cancellable;

		public ScriptRunner (Session session, string? script_path, string? script_source, ScriptRuntime script_runtime,
				Json.Node parameters, bool enable_development, Cancellable io_cancellable) {
			this.session = session;
			this.script_path = script_path;
			this.script_source = script_source;
			this.script_runtime = script_runtime;
			this.parameters = parameters;
			this.enable_development = enable_development;
			this.io_cancellable = io_cancellable;
		}

		construct {
			rpc_client = new RpcClient (this);
		}

		public async void start () throws Error, IOError {
			save_terminal_config ();

			yield load ();

			if (enable_development && script_path != null) {
				try {
					script_monitor = File.new_for_path (script_path).monitor_file (FileMonitorFlags.NONE);
					script_monitor.changed.connect (on_script_file_changed);
				} catch (GLib.Error e) {
					printerr (e.message + "\n");
				}
			}
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			if (script_monitor != null) {
				script_monitor.changed.disconnect (on_script_file_changed);
				script_monitor.cancel ();
				script_monitor = null;
			}

			yield session.detach (cancellable);

			restore_terminal_config ();
		}

		private async void try_reload () {
			try {
				yield load ();
			} catch (GLib.Error e) {
				printerr ("Failed to reload script: %s\n", e.message);
			}
		}

		private async void load () throws Error, IOError {
			load_in_progress = true;

			try {
				string source;

				var options = new ScriptOptions ();

				if (script_path != null) {
					try {
						FileUtils.get_contents (script_path, out source);
					} catch (FileError e) {
						throw new Error.INVALID_ARGUMENT ("%s", e.message);
					}

					options.name = Path.get_basename (script_path).split (".", 2)[0];
				} else {
					source = script_source;

					options.name = "frida";
				}

				options.runtime = script_runtime;

				var s = yield session.create_script (source, options, io_cancellable);

				if (script != null) {
					yield script.unload (io_cancellable);
					script = null;
				}
				script = s;

				script.message.connect (on_message);
				yield script.load (io_cancellable);

				yield call_init ();

				terminal_mode = yield query_terminal_mode ();
				apply_terminal_mode (terminal_mode);

				if (eternalize)
					yield script.eternalize (io_cancellable);
			} finally {
				load_in_progress = false;
			}
		}

		private async void call_init () {
			var stage = new Json.Node.alloc ().init_string ("early");

			try {
				yield rpc_client.call ("init", new Json.Node[] { stage, parameters }, null, io_cancellable);
			} catch (GLib.Error e) {
			}
		}

#if WINDOWS
		private void save_terminal_config () throws Error {
		}

		private void restore_terminal_config () {
		}

		private async TerminalMode query_terminal_mode () {
			return COOKED;
		}

		private void apply_terminal_mode (TerminalMode mode) throws Error {
		}
#else
		private void save_terminal_config () throws Error {
			var fd = stdin.fileno ();
			if (Posix.tcgetattr (fd, out original_term) == -1) {
				if (Posix.errno == 25)  /* ENOTTY */
					original_term = null;
				else
					throw new Error.INVALID_OPERATION ("tcgetattr failed: %s", strerror (Posix.errno));
			}
		}

		private void restore_terminal_config () {
			if (original_term == null)
				return;

			var fd = stdin.fileno ();
			Posix.tcsetattr (fd, Posix.TCSANOW, original_term);
			stdout.putc ('\r');
			stdout.flush ();
		}

		private async TerminalMode query_terminal_mode () {
			Json.Node mode_value;
			try {
				mode_value = yield rpc_client.call ("getFridaTerminalMode", new Json.Node[] {}, null, io_cancellable);
			} catch (GLib.Error e) {
				return COOKED;
			}

			if (mode_value.get_value_type () != typeof (string))
				return COOKED;

			switch (mode_value.get_string ()) {
				case "raw":
					return TerminalMode.RAW;
				case "binary":
					return TerminalMode.BINARY;
				default:
					return TerminalMode.COOKED;
			}
		}

		private void apply_terminal_mode (TerminalMode mode) throws Error {
			if (mode == COOKED || original_term == null)
				return;

			int fd = stdin.fileno ();

			Posix.termios term;
			if (Posix.tcgetattr (fd, out term) == -1)
				throw new Error.INVALID_OPERATION ("tcgetattr() failed: %s", strerror (Posix.errno));

			term.c_iflag &= ~Posix.BRKINT;
			term.c_iflag &= ~Posix.ICRNL;
			term.c_iflag &= ~Posix.INPCK;
			term.c_iflag &= ~Posix.ISTRIP;
			term.c_iflag &= ~Posix.IXON;

			term.c_oflag &= ~Posix.OPOST;

			term.c_cflag |= Posix.CS8;

			term.c_lflag &= ~Posix.ECHO;
			term.c_lflag &= ~Posix.ICANON;
			term.c_lflag &= ~Posix.IEXTEN;
			term.c_lflag |= Posix.ISIG;

			if (Posix.tcsetattr (fd, Posix.TCSANOW, term) == -1)
				throw new Error.INVALID_OPERATION ("tcsetattr() failed: %s", strerror (Posix.errno));
		}
#endif

		public void on_stdin (string str, Bytes? data) {
			var str_value = new Json.Node.alloc ().init_string (str);

			rpc_client.call.begin ("onFridaStdin", new Json.Node[] { str_value }, data, io_cancellable);
		}

		private void on_script_file_changed (File file, File? other_file, FileMonitorEvent event_type) {
			if (event_type == FileMonitorEvent.CHANGES_DONE_HINT)
				return;

			var source = new TimeoutSource (50);
			source.set_callback (() => {
				if (load_in_progress)
					return true;
				try_reload.begin ();
				return false;
			});
			source.attach (Frida.get_main_context ());

			if (script_unchanged_timeout != null)
				script_unchanged_timeout.destroy ();
			script_unchanged_timeout = source;
		}

		private void on_message (string json, Bytes? data) {
			bool handled = rpc_client.try_handle_message (json);
			if (handled)
				return;

			var parser = new Json.Parser ();
			try {
				parser.load_from_data (json);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			var message = parser.get_root ().get_object ();

			var type = message.get_string_member ("type");
			switch (type) {
				case "log":
					handled = try_handle_log_message (message);
					break;
				case "send":
					handled = try_handle_stdout_message (message, data);
					break;
				default:
					handled = false;
					break;
			}

			if (!handled) {
				stdout.puts (json);
				stdout.putc ('\n');
			}
		}

		private bool try_handle_log_message (Json.Object message) {
			var level = message.get_string_member ("level");
			var payload = message.get_string_member ("payload");
			switch (level) {
				case "info":
					print ("%s\n", payload);
					break;

				case "warning":
					printerr ("\033[0;33m%s\033[0m\n", payload);
					break;

				case "error":
					printerr ("\033[0;31m%s\033[0m\n", payload);
					break;
			}
			return true;
		}

		/**
		 * The script can send strings to frida-inject to write to its stdout or
		 * stderr. This can be done either inside the RPC handler for receiving
		 * input from frida-inject, or elsewhere at any arbitrary point in the
		 * script. We use the following syntax:
		 *
		 * send(['frida:stdout', 'DATA']);
		 * send(['frida:stderr', 'DATA']);
		 *
		 * The resulting message will look as shown below. Note that we don't
		 * use the parent object's `type` field since this is reserved for use
		 * by the runtime itself.
		 *
		 * {"type":"send","payload":["frida:stdout","DATA"]}
		 */
		private bool try_handle_stdout_message (Json.Object message, Bytes? data) {
			var payload = message.get_member ("payload");
			if (payload.get_node_type () != Json.NodeType.ARRAY)
				return false;

			var tuple = payload.get_array ();
			var tuple_len = tuple.get_length ();
			if (tuple_len == 0)
				return false;

			var type = tuple.get_element (0).get_string ();
			if (type == null)
				return false;
			switch (type) {
				case "frida:stdout":
				case "frida:stderr":
					break;
				default:
					return false;
			}

			if (tuple_len >= 2) {
				var str = tuple.get_element (1).get_string ();
				if (str == null)
					return false;

				switch (type) {
					case "frida:stdout":
						stdout.write (str.data);
						stdout.flush ();
						break;
					case "frida:stderr":
						stderr.write (str.data);
						break;
					default:
						return false;
				}
			}

			if (data != null) {
				switch (type) {
					case "frida:stdout":
						stdout.write (data.get_data ());
						stdout.flush ();
						break;
					case "frida:stderr":
						stderr.write (data.get_data ());
						break;
					default:
						return false;
				}
			}

			return true;
		}

		private async void post_rpc_message (string json, Bytes? data, Cancellable? cancellable) throws Error, IOError {
			script.post (json, data);
		}
	}

	private enum TerminalMode {
		COOKED,
		RAW,
		BINARY
	}
}

"""

```