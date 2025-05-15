# WiFighter

A  Python CLI tool created with `argparse` to capture and optionally crack WPA/WPA2 handshakes using `aircrack-ng` and/or `hashcat`. Developed for security researchers and enthusiasts to test their own networks ethically.

## Features
- **Handshake Capture**: Automates deauthentication and handshake capture with retries.
- **Password Cracking**: `aircrack-ng` and `hashcat` with a provided wordlist (defaiult path and wordlist rockyou.txt).
- **Progress Bars**: Visual feedback during scanning with `tqdm`.
- **Non-Interactive Mode**: Run without prompts for scripting.
- **Logging**: Saves detailed logs to file.
- **Config File**: Load defaults from `wifighter.ini`.
- **Output Directory**: Custom ` 'izable location for captured files.
- **Adapter Check**: Verifies Wi-Fi adapter compatibility.
- **Colored Output**: Red (errors), Green (success), Blue (informational), Yellow (warnings).

## Prerequisites
- **OS**: Any Linux distro with `aircrack-ng` installed.
- **Hardware**: Wi-Fi adapter supporting monitor mode and packet injection (e.g., Alfa AWUS036NHA).
- **Software**:
  - `aircrack-ng` (`sudo apt install aircrack-ng`)
  - `hashcat` (`sudo apt install hashcat`)
  - `cap2hccapx` (download from [Hashcat Utils](https://hashcat.net/tools/))
  - Python 3.x with `tqdm` (`pip install tqdm`)

## Installation
1. Clone the repository:
     `git clone https://github.com/yourusername/wifighter.git`
     `cd wifighter`
2. Make the script executable
  `chmod +x wifighter.py`
3. Install Python dependencies
4. Execute
   `sudo ./wifighter.py`

   

   
       
