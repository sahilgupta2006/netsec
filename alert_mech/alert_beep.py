import sys
import os
import threading

beep_lock = threading.Lock()

def beep(frequency=1000, duration=300):
    """Generate a beep sound.

    Args:
        frequency (int): Frequency in Hz (ignored on non-Windows).
        duration (int): Duration in milliseconds (ignored on macOS).
    """
    if sys.platform == "win32":
        import winsound
        winsound.Beep(frequency, duration)
    elif sys.platform == "darwin":
        os.system("osascript -e 'beep'")
    else:
        os.system("printf '\\a'")  # ANSI escape for Linux