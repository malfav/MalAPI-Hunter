Description:
MalAPI Hunter is an IDA Pro plugin designed for advanced static malware analysis. It automatically identifies, classifies, and highlights suspicious Windows API calls across multiple categories such as process injection, evasion, anti-debugging, networking, and cryptography. The plugin integrates a large curated database of Win32, Native NT, and DLL-specific APIs, enabling analysts to quickly understand malicious behavior patterns. It also provides a structured GUI panel for efficient navigation, categorization, and analysis of API usage, significantly improving reverse engineering workflow and detection accuracy.

Features:

- Automatic detection of suspicious API calls
- Categorization (Injection, Evasion, Anti-Debugging, etc.)
- Large API database (Win32, Native NT, DLL)
- Instruction highlighting inside IDA
- GUI panel for navigation and filtering
- Fast static behavior overview
- Supports reverse engineering workflows
- Hotkey access (Ctrl+Shift+A)

Installation:

- Copy mal_api_hunter.py into:
- C:\Users\your_username\AppData\Roaming\Hex-Rays\IDA Pro\plugins
- Restart IDA Pro
- The plugin will load automatically

- Usage:

- Open a binary in IDA Pro
- Press Ctrl+Shift+A to launch the plugin
- Browse detected APIs in the GUI panel
- Click entries to navigate to code locations
- Analyze categorized behavior for faster triage
