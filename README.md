# WiFighter

A  Python CLI tool to capture and optionally crack WPA/WPA2 handshakes using Kali Linux and `aircrack-ng` or `hashcat`. Designed for security researchers and enthusiasts to test their own networks legally.

## Features
- **Handshake Capture**: Automates deauthentication and handshake capture with retries.
- **Password Cracking**: Supports `aircrack-ng` and `hashcat` with a provided wordlist.
- **Progress Bars**: Visual feedback during scanning with `tqdm`.
- **Non-Interactive Mode**: Run without prompts for scripting.
- **Logging**: Saves detailed logs to a file.
- **Config File**: Load defaults from `wifighter.ini`.
- **Output Directory**: Customizable location for captured files.
- **Adapter Check**: Verifies Wi-Fi adapter compatibility.
- **Colored Output**: Red (errors), Green (success), Blue (info), Yellow (warnings).

## Prerequisites
- **OS**: Kali Linux (or similar with `aircrack-ng` installed).
- **Hardware**: Wi-Fi adapter supporting monitor mode and packet injection (e.g., Alfa AWUS036NHA).
- **Software**:
  - `aircrack-ng` (`sudo apt install aircrack-ng`)
  - `hashcat` (optional, for GPU cracking: `sudo apt install hashcat`)
  - `cap2hccapx` (optional, for Hashcat: download from [Hashcat Utils](https://hashcat.net/tools/))
  - Python 3.x with `tqdm` (`pip install tqdm`)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/wifighter.git
   cd wifighter
   ```
2. Make the script executable
  ```bash
  chmod +x wifighter.py
  ```
3. Install Python dependencies
   ```bash
    chmod +x wifighter.py
   ```
4. Execute
   ```bash
   sudo ./wifighter.py
   ```

   

   
       
