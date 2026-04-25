# MalAPI Hunter

MalAPI Hunter is an IDA Pro plugin designed for advanced static malware analysis. It automatically identifies, classifies, and highlights suspicious Windows API calls across categories such as process injection, evasion, anti-debugging, networking, and cryptography. The plugin integrates a curated database of Win32, Native NT, and DLL-specific APIs, enabling fast understanding of malicious behavior patterns and improving reverse engineering accuracy. It provides instruction-level highlighting inside IDA and a structured GUI panel for navigation, filtering, and analysis of API usage, significantly improving static analysis workflow and detection efficiency. The plugin is accessed via the hotkey Ctrl + Shift + A after installation.


![image_alt](https://github.com/malfav/MalAPI-Hunter/blob/main/Interface.png?raw=true)

# API's Database 

![image_alt](https://github.com/malfav/MalAPI-Hunter/blob/main/API_Database.png?raw=true)


## Features
- Automatic detection of suspicious API calls  
- Categorization (Injection, Evasion, Anti-Debugging, Networking, Cryptography, etc.)  
- Large API database (Win32, Native NT, DLL-specific APIs)  
- Instruction-level highlighting inside IDA  
- GUI panel for navigation and filtering  
- Fast static behavioral overview  
- Reverse engineering workflow optimization  

## Installation & Usage

- mal_api_hunter.py must be copied into: C:\Users\your_username\AppData\Roaming\Hex-Rays\IDA Pro\plugins

## Note : 

- After placing the file, restart IDA Pro. Open a binary, press Ctrl + Shift + A, and use the GUI panel to browse detected APIs, navigate to code locations, and analyze categorized behavior for faster triage.

![image_alt](https://github.com/malfav/MalAPI-Hunter/blob/main/Usage.png?raw=true)


## Use Cases
- Malware triage, static behavior analysis, reverse engineering acceleration, and detection of injection, evasion, anti-debugging, and other malicious techniques.


## Requirements
- IDA Pro with Python support.

## Demonstration


[![Watch demo](https://img.youtube.com/vi/CipujqFdWxM/hqdefault.jpg)](https://www.youtube.com/watch?v=CipujqFdWxM)
