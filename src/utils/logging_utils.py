import traceback

def exc_to_text(e: Exception) -> str:
    return f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
