# Kodi USB Binder Manager for LG webOS TVs (macOS)

## ⚠️ Important Notes ⚠️

* **ROOTED LG webOS TV REQUIRED**: This software only works with **rooted** LG webOS TVs with SSH access. Stock TVs are **NOT** supported.
* **NO SYSTEM-LEVEL INTERFERENCE**: This application **does not perform permanent system-level modifications** on your macOS or LG webOS TV. It sets up scripts and services that can be easily removed via the "Remove All Scripts" function within the app.
* **SINGLE-USE SETUP TOOL**: This application is used **once** for initial setup. After completing all 3 steps, you can delete this app. The USB binding will continue to work automatically.
* **MACBOOK MUST BE ON**: The automatic USB drive mounting **only functions when your macOS laptop is powered on** and running the background monitoring script.

---

## 🎬 Project Overview

This macOS application automates the process of mounting USB media drives for Kodi on LG webOS TVs. It provides a user-friendly graphical interface (GUI) to simplify the setup of a robust background system.

### How it Works:
1.  **TV-Side Script**: An SSH script (`usb_bind_kodi.sh`) runs on your LG TV to detect and mount USB drives to Kodi's media directory (`/mnt/lg/user/var/palm/jail/org.xbmc.kodi/media/usbdrive`).
2.  **macOS Monitoring Script**: A background script (`kodi_usb_binder.sh`) runs on your Mac, periodically checking the TV's online status.
3.  **Automatic Trigger**: When the TV comes online (e.g., after power-up or waking from sleep), the macOS script triggers the TV-side script via SSH to mount the USB drives.
4.  **Autostart**: A macOS LaunchAgent ensures the monitoring script starts automatically with every Mac reboot.

---

## 🚀 System Requirements & Setup

### Requirements:
* **Rooted LG webOS TV** with SSH enabled.
* **macOS** computer (laptop/desktop) on the same local network as the TV.
* The macOS computer must be **powered on and active** for the automated mounting to occur.
* Kodi installed on your LG webOS TV.

### First-Time Setup (using the App):
The application's GUI will guide you through the following essential steps:
1.  Enter your TV's IP address.
2.  Generate a secure SSH key pair on your Mac.
3.  Authorize the generated SSH public key on your LG TV (you'll paste a command into Terminal and may need to enter the TV's default `alpine` password once).
4.  Copy the TV-side script to your TV.
5.  Create the local macOS monitoring script.
6.  Set up the macOS Autostart service (LaunchAgent).

---

## 👨‍💻 Building the macOS Application (`.app`)

To create a standalone `.app` bundle from the Python script using PyInstaller:

1.  **Install PyInstaller** (if you haven't already):
    ```bash
    pip install pyinstaller
    ```
2.  **Navigate to your script directory** in Terminal:
    ```bash
    cd "/path/to/your/project/folder"
    # Example: cd "/Users/yourusername/Documents/Kodi_USB_Binder Project"
    ```
3.  **Run PyInstaller** to build the application:
    ```bash
    pyinstaller --noconfirm --windowed --name "Kodi USB Binder" "kodi_binder.final.py"
    ```
    The `.app` file will be generated in the `dist` subfolder within your project directory (e.g., `/path/to/your/project/folder/dist/Kodi USB Binder.app`).

---

## 🗑️ Removal

The application includes a **"Remove All Scripts"** button in its GUI to uninstall all components (stops LaunchAgent, deletes local scripts/logs, and attempts to remove the TV-side script).

---

## 🤝 Acknowledgements

Special thanks to Gemini AI for assistance in refining this project.