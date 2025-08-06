# ⚡ iec104sniffer: IEC 60870-5-104 Protocol Sniffer

`iec104sniffer` is a command-line interface (CLI) tool designed to capture and decode IEC 60870-5-104 protocol frames. It provides advanced sniffing capabilities, allowing users to monitor communication on specified network interfaces and ports, with options for filtering by data type and information object address.

## ✨ Features

* **Network Interface Discovery**: Automatically identifies network interfaces by IP address.
* **Multi-Port Listening**: Supports sniffing on multiple TCP ports simultaneously.
* **IEC 104 APDU Decoding**: Decodes I-frames (Information), S-frames (Supervision), and U-frames (Unnumbered Control).
* **Information Object Parsing**:
    * **Measured Value, Normalized (M_ME_NA_1)**: Decodes analog values with Quality Descriptors (QDS).
    * **Single-Point Information with Time Tag (M_SP_TB_1)**: Decodes digital single-point information with CP56Time2a timestamps.
    * **Double-Point Information with Time Tag (M_DP_TB_1)**: Decodes digital double-point information with CP56Time2a timestamps.
* **Filtering Capabilities**:
    * **Type Filtering**: Filter displayed output by data type (e.g., `analog`, `digital`, `double`, `control`).
    * **Point Filtering**: Specify a list of information object addresses (points) to monitor.
* **Raw Packet Output**: Option to display the complete raw hexadecimal dump of captured packets for detailed analysis.
* **Concurrency**: Utilizes Go routines for concurrent packet processing, enhancing performance.

## 🚀 Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

* **Go (Golang)**: Ensure you have Go installed (version 1.16 or higher is recommended). You can download it from [golang.org](https://golang.org/dl/).
* **Npcap (Windows)** or **libpcap-dev (Linux/macOS)**: `iec104sniffer` uses `gopacket` which relies on `pcap` for packet capture.
    * **Windows**: Download and install [Npcap](https://nmap.org/npcap/1). Make sure to check "Install Npcap in WinPcap API-compatible Mode" during installation if you encounter issues.
    * **Linux/macOS**: Install the `libpcap-dev` package (or equivalent) for your distribution.
        * Debian/Ubuntu: `sudo apt-get install libpcap-dev`
        * RedHat/CentOS: `sudo yum install libpcap-devel`
        * macOS (with Homebrew): `brew install libpcap`

### Installation

1.  **Clone the repository:**

    ```bash
    git clone [https://github.com/eduard-mazo/iec104sniffer.git](https://github.com/eduard-mazo/iec104sniffer.git)
    cd iec104sniffer
    ```

2.  **Build the application:**

    ```bash
    go build -o 104Scan .
    ```
    This command will compile the Go source code and create an executable named `104Scan` in the project root directory.

## 💻 Usage

The `iec104sniffer` tool has two main commands: `list-interfaces` and `sniff`.

### `list-interfaces`

This command helps you identify the available network interfaces on your system, which is crucial for specifying the `--ip` flag for the `sniff` command.

```bash
./104Scan list-interfaces