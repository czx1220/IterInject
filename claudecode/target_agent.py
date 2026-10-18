"""
目标 Agent 执行模块
负责启动目标 Claude 实例并捕获输出
使用 MiniMax-M2.1 (通过 start_clean_claude.sh)

v2: 新增 --output-format json 捕获 tool call 信息
"""
import json
import subprocess
from pathlib import Path
from config import BASE_DIR, TASK_PROMPT, START_SCRIPT, LOGS_DIR, EXECUTION_TIMEOUT


class TargetAgent:
    """目标 Agent - 负责执行任务并返回响应"""

    def __init__(self):
        # 确保日志目录存在
        LOGS_DIR.mkdir(parents=True, exist_ok=True)

    def execute(self, output_format: str = "text") -> str:
        """
        执行目标 agent

        Args:
            output_format: "text" 只捕获文本输出（兼容旧逻辑），
                          "json" 捕获结构化 JSON 输出含 tool call 信息

        Returns:
            agent 的完整输出（stdout + stderr）
        """
        # 读取任务 prompt
        with open(TASK_PROMPT, 'r') as f:
            task_content = f.read()

        # 将 prompt 写入临时文件
        prompt_file = LOGS_DIR / "temp_prompt.txt"
        with open(prompt_file, 'w') as f:
            f.write(task_content)

        # 构建命令
        if output_format == "json":
            # 使用 JSON 输出格式，捕获 tool call 信息
            cmd = f'bash {START_SCRIPT} --permission-mode auto --output-format json -p "$(cat {prompt_file})"'
        else:
            cmd = f'bash {START_SCRIPT} --permission-mode auto -p "$(cat {prompt_file})"'

        try:
            result = subprocess.run(
                ['bash', '-c', cmd],
                capture_output=True,
                text=True,
                timeout=EXECUTION_TIMEOUT,
                cwd=str(BASE_DIR)
            )
            # 分离 stdout 和 stderr
            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
        except subprocess.TimeoutExpired:
            output = "TIMEOUT: Execution exceeded time limit"
        except Exception as e:
            output = f"ERROR: {str(e)}"

        return output

    def execute_with_tool_calls(self) -> dict:
        """
        执行目标 agent 并解析 tool call 信息

        Returns:
            {
                "text_output": str,      # Agent 文本输出（兼容旧评估逻辑）
                "tool_calls": list,      # Tool call 列表
                "raw_json": dict/list,    # 原始 JSON 输出
                "tools_used": list,      # 使用的工具名列表
                "bash_commands": list,   # 执行的 bash 命令列表
                "files_written": list,   # 写入的文件列表
                "files_read": list,      # 读取的文件列表
            }
        """
        raw_output = self.execute(output_format="json")

        result = {
            "text_output": raw_output,
            "tool_calls": [],
            "raw_json": None,
            "tools_used": [],
            "bash_commands": [],
            "files_written": [],
            "files_read": [],
        }

        # 尝试解析 JSON 输出
        try:
            # Claude Code --output-format json 可能输出多行 JSON 或单个 JSON
            raw_output_stripped = raw_output.strip()

            # 尝试直接解析
            try:
                parsed = json.loads(raw_output_stripped)
            except json.JSONDecodeError:
                # 可能是 stream-json 格式，每行一个 JSON
                parsed = []
                for line in raw_output_stripped.split('\n'):
                    line = line.strip()
                    if line:
                        try:
                            parsed.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

            result["raw_json"] = parsed

            # 从 JSON 中提取 tool call 信息
            tool_calls = []
            tools_used = set()
            bash_commands = []
            files_written = []
            files_read = []

            messages = parsed if isinstance(parsed, list) else [parsed]

            for msg in messages:
                # 处理不同格式的 JSON 输出
                if isinstance(msg, dict):
                    # 检查是否有 tool_use content blocks
                    content = msg.get("content", [])
                    if isinstance(content, str):
                        continue
                    if isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "tool_use":
                                tool_name = block.get("name", "")
                                tool_input = block.get("input", {})
                                tool_calls.append({
                                    "name": tool_name,
                                    "input": tool_input,
                                    "id": block.get("id", ""),
                                })
                                tools_used.add(tool_name)

                                # 提取特定工具的参数
                                if tool_name == "Bash":
                                    cmd = tool_input.get("command", "")
                                    if cmd:
                                        bash_commands.append(cmd)
                                elif tool_name == "Write":
                                    fp = tool_input.get("file_path", "")
                                    if fp:
                                        files_written.append(fp)
                                elif tool_name == "Edit":
                                    fp = tool_input.get("file_path", "")
                                    if fp:
                                        files_written.append(fp)
                                elif tool_name == "Read":
                                    fp = tool_input.get("file_path", "")
                                    if fp:
                                        files_read.append(fp)

                    # 检查 result 字段（有些输出格式）
                    if "result" in msg:
                        result_content = msg["result"]
                        if isinstance(result_content, list):
                            for block in result_content:
                                if isinstance(block, dict) and block.get("type") == "tool_use":
                                    tool_name = block.get("name", "")
                                    tool_input = block.get("input", {})
                                    tool_calls.append({
                                        "name": tool_name,
                                        "input": tool_input,
                                        "id": block.get("id", ""),
                                    })
                                    tools_used.add(tool_name)

            result["tool_calls"] = tool_calls
            result["tools_used"] = list(tools_used)
            result["bash_commands"] = bash_commands
            result["files_written"] = files_written
            result["files_read"] = files_read

            # 提取最终文本输出
            text_parts = []
            for msg in messages:
                if isinstance(msg, dict):
                    content = msg.get("content", "")
                    if isinstance(content, str) and content:
                        text_parts.append(content)
                    elif isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "text":
                                text_parts.append(block.get("text", ""))
            if text_parts:
                result["text_output"] = "\n".join(text_parts)

        except Exception as e:
            # JSON 解析失败，使用原始文本输出
            result["text_output"] = raw_output

        return result

    def execute_with_log(self, log_file: Path, output_format: str = "text") -> str:
        """
        执行目标 agent 并保存日志

        Args:
            log_file: 保存输出的文件路径
            output_format: 输出格式

        Returns:
            agent 的完整输出
        """
        output = self.execute(output_format=output_format)

        # 保存到日志文件
        with open(log_file, 'w') as f:
            f.write(output)

        return output