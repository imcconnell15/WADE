@dataclass
class CommandResult:
    rc: int
    stdout: str
    stderr: str
    duration_sec: float

def safe_run(
    cmd: List[str],
    timeout: int = 60,
    check: bool = False,
    log_output: bool = True,
    env: Optional[Dict[str, str]] = None,
) -> CommandResult:
    """
    Run command with consistent error handling.
    - Auto-logs command + duration
    - Truncates stderr to 200 chars
    - Raises ToolExecutionError if check=True and rc != 0
    """
