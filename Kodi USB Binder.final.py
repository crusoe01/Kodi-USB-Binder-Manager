import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import threading
import random
import os
import re
import ipaddress

# --- Script content for the TV-side (usb_bind_kodi.sh) ---
# This script directly mounts USB devices to the Kodi directory on the TV.
usb_bind_kodi_sh_content = """#!/bin/bash
LOG_FILE="/tmp/usb_bind_kodi.log"
KODI_USB_DIR="/mnt/lg/user/var/palm/jail/org.xbmc.kodi/media/usbdrive"
MEDIA_FILES=("mp4" "mkv" "avi" "mov" "mp3" "flac" "jpg" "jpeg" "png")

log() {
    echo "$(date '+%m.%d.%Y - %H:%M:%S') - $1" >> "$LOG_FILE"
}

log "Script started."

# Ensure Kodi USB directory exists
if [ ! -d "$KODI_USB_DIR" ]; then
    log "Creating Kodi USB directory: $KODI_USB_DIR"
    mkdir -p "$KODI_USB_DIR"
    if [ $? -ne 0 ]; then
        log "Failed to create $KODI_USB_DIR. Exiting."
        exit 1
    fi
fi

# Clean up stale mounts
log "Checking for stale mounts in $KODI_USB_DIR..."
MOUNTED_DEVICES=$(mount | grep "$KODI_USB_DIR" | awk '{print $1}')
if [ -n "$MOUNTED_DEVICES" ]; then
    log "Found existing mounts: $MOUNTED_DEVICES. Unmounting..."
    for dev in $MOUNTED_DEVICES; do
        umount "$dev"
        if [ $? -eq 0 ]; then
            log "Successfully unmounted $dev."
        else
            log "Failed to unmount $dev."
        fi
    done
else
    log "No stale mounts found."
fi

# Find USB drives
log "Searching for USB block devices..."
USB_DEVICES=$(ls /sys/block/sd* /sys/block/mmcblk* 2>/dev/null | grep -E 'sd[a-z]+|mmcblk[0-9]+' | xargs -n 1 basename)

FOUND_USB=0
for dev in $USB_DEVICES; do
    log "Processing device: /dev/$dev"
    # Iterate through partitions
    PARTITIONS=$(ls /dev/${dev}[0-9]* 2>/dev/null)
    if [ -z "$PARTITIONS" ]; then
        PARTITIONS="/dev/$dev" # If no partitions, try to mount the device itself
    fi

    for part in $PARTITIONS; do
        log "Attempting to mount partition: $part"
        # Try to mount with different file systems
        for fstype in "vfat" "ntfs" "exfat" "ext4" "ext3" "ext2"; do
            mount -t "$fstype" "$part" "$KODI_USB_DIR" 2>/dev/null
            if [ $? -eq 0 ]; then
                log "Successfully mounted $part as $fstype to $KODI_USB_DIR"
                FOUND_USB=1
                # Check for media files after successful mount
                MEDIA_FOUND=0
                for ext in "${MEDIA_FILES[@]}"; do
                    find "$KODI_USB_DIR" -maxdepth 3 -iname "*.${ext}" -print -quit | grep -q .
                    if [ $? -eq 0 ]; then
                        log "Media files (e.g., *.$ext) found on $part. Keeping mounted."
                        MEDIA_FOUND=1
                        break
                    fi
                done

                if [ $MEDIA_FOUND -eq 0 ]; then
                    log "No common media files found on $part within 3 subdirectories. Unmounting."
                    umount "$part"
                    if [ $? -eq 0 ]; then
                        log "Successfully unmounted $part due to no media files."
                    else
                        log "Failed to unmount $part after no media found."
                    fi
                fi
                break # Break from fstype loop if successfully mounted
            else
                log "Failed to mount $part as $fstype."
            fi
        done
        if [ $FOUND_USB -eq 1 ] && [ $MEDIA_FOUND -eq 1 ]; then
            break # Break from partition loop if a suitable media partition is found and mounted
        fi
    done
    if [ $FOUND_USB -eq 1 ] && [ $MEDIA_FOUND -eq 1 ]; then
        break # Break from device loop if a suitable media device/partition is found and mounted
    fi
done

if [ $FOUND_USB -eq 0 ] || [ $MEDIA_FOUND -eq 0 ]; then
    log "No suitable USB device with media found or mounted."
    # Ensure the mount point is clean if nothing was mounted
    if mountpoint -q "$KODI_USB_DIR"; then
        log "WARNING: $KODI_USB_DIR is still mounted but no media was confirmed. Attempting unmount."
        umount "$KODI_USB_DIR"
    fi
else
    log "USB bind process completed. Check Kodi for media."
fi

log "Script finished."
"""

# --- Script content for the macOS monitoring (kodi_usb_binder.sh) ---
# This script runs on macOS and monitors the TV's state, triggering the TV-side script.
kodi_usb_binder_sh_content = """#!/bin/bash
# --- Configuration ---
# IMPORTANT: Replace with your TV's actual IP address
TV_IP="{TV_IP_PLACEHOLDER}"
# IMPORTANT: Replace with the actual path to your SSH private key on your Mac
SSH_KEY="{SSH_KEY_PLACEHOLDER}"
SSH_USER="root"
LOGFILE="$HOME/kodi_usb_binder.log"
STATEFILE="$HOME/.tv_bind_state"
MAX_LOG_LINES=1000 # Max lines for the log file before it's truncated

# --- Timestamp formatting ---
timestamp() {
    date "+%m.%d.%Y - %H:%M:%S"
}

# --- Log rotation: clear log if too long ---
# This prevents the log file from growing indefinitely
if [ -f "$LOGFILE" ] && [ "$(wc -l < "$LOGFILE")" -gt "$MAX_LOG_LINES" ]; then
    > "$LOGFILE" # Truncate log file
    echo "$(timestamp): Log file truncated due to size limit." >> "$LOGFILE"
fi

# --- Read previous state ---
PREV_STATE="unknown"
if [ -f "$STATEFILE" ]; then
    PREV_STATE=$(cat "$STATEFILE")
fi

# --- Try SSH connection with timeout, capture output ---
# Use a short timeout to quickly determine if TV is online
SSH_OUTPUT=$(ssh -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=3 "$SSH_USER@$TV_IP" "echo TV_OK" 2>&1)
SSH_STATUS=$?

if [ $SSH_STATUS -eq 0 ] && echo "$SSH_OUTPUT" | grep -q "TV_OK"; then
    CURRENT_STATE="reachable"
else
    CURRENT_STATE="unreachable"
fi

# --- React only if state has changed ---
if [ "$CURRENT_STATE" != "$PREV_STATE" ]; then
    echo "$CURRENT_STATE" > "$STATEFILE" # Save current state

    case "$CURRENT_STATE" in
        reachable)
            echo "$(timestamp): TV is reachable again." >> "$LOGFILE"
            echo "$(timestamp): Attempting to trigger USB bind script on TV." >> "$LOGFILE"
            # Execute the TV-side script, capturing its output to the local log
            ssh -i "$SSH_KEY" "$SSH_USER@$TV_IP" '
                if mount | grep -q "/mnt/lg/user/var/palm/jail/org.xbmc.kodi/media/usbdrive"; then
                    echo "Kodi USB directory already mounted. No action needed on TV."
                else
                    echo "Kodi USB directory not mounted. Running usb_bind_kodi.sh on TV..."
                    sh /media/developer/usb_bind_kodi.sh
                fi
            ' >> "$LOGFILE" 2>&1 || echo "$(timestamp): Error during TV-side script execution." >> "$LOGFILE"
            ;;
        unreachable)
            echo "$(timestamp): TV is offline." >> "$LOGFILE"
            ;;
    esac
fi

exit 0
"""

class KodiBinderApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Kodi USB Binder Manager")
        self.geometry("900x600")
        self.minsize(850, 550)

        self.ssh_key_path = tk.StringVar()
        self.tv_ip = tk.StringVar(value="") # No pre-filled IP here
        self.ssh_key_content = tk.StringVar()

        self.key_generated = False # Track if key is generated
        self.ssh_test_successful = False # Track if SSH test passed
        self.initial_setup_completed = False # Track full setup completion (can be saved to config later)

        # Style for the red background/white text label
        self.style = ttk.Style()
        self.style.configure("Red.TLabel", background="red", foreground="white", font=("Helvetica", 12, "bold"))


        self.create_widgets()
        
        # Always set the main window close protocol
        self.protocol("WM_DELETE_WINDOW", self.on_main_window_close)

        # Show modal on app start ONLY if initial setup hasn't been completed yet
        # For a persistent app, you'd save/load initial_setup_completed from a file
        if not self.initial_setup_completed:
            self.show_first_run_modal()


    def create_widgets(self):
        # --- Main Layout Frames ---
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side="left", fill="y", expand=False)

        right_frame = ttk.Frame(main_frame, width=300)
        right_frame.pack(side="right", fill="y", expand=False, padx=(20,0))

        bottom_frame = ttk.Frame(self, relief="sunken", borderwidth=1)
        bottom_frame.pack(side="bottom", fill="both", expand=True, padx=10, pady=(0,10))

        # --- Left Frame: TV IP & SSH Key Section ---
        ttk.Label(left_frame, text="TV IP Address:").pack(anchor="w", pady=(0,2))
        self.tv_ip_entry = ttk.Entry(left_frame, textvariable=self.tv_ip, width=25)
        self.tv_ip_entry.pack(anchor="w", pady=(0,6))

        ip_button_frame = ttk.Frame(left_frame)
        ip_button_frame.pack(anchor="w", pady=(0,8))
        
        self.ping_button = ttk.Button(ip_button_frame, text="Ping TV", command=self.ping_tv)
        self.ping_button.pack(side="left")
        
        self.test_ssh_button = ttk.Button(ip_button_frame, text="Test SSH", command=self.test_ssh_connection)
        self.test_ssh_button.pack(side="left", padx=(5,0))

        ttk.Separator(left_frame, orient="horizontal").pack(fill="x", pady=10)

        self.generate_key_button = ttk.Button(left_frame, text="Generate New SSH Key", command=self.generate_ssh_key)
        self.generate_key_button.pack(anchor="w", pady=(0,10))

        ttk.Label(left_frame, text="SSH Private Key Path:").pack(anchor="w", pady=(0,2))
        key_path_frame = ttk.Frame(left_frame)
        key_path_frame.pack(anchor="w", fill="x", pady=(0,6))
        self.key_path_entry = ttk.Entry(key_path_frame, textvariable=self.ssh_key_path, width=40)
        self.key_path_entry.pack(side="left", fill="x", expand=True)
        self.browse_button = ttk.Button(key_path_frame, text="Browse", command=self.browse_ssh_key)
        self.browse_button.pack(side="left", padx=(5,0))

        ttk.Label(left_frame, text="SSH Key Content:").pack(anchor="w", pady=(0,2))
        self.key_content_text = tk.Text(left_frame, height=10, width=50, wrap="none")
        self.key_content_text.pack(fill="both", expand=False)
        self.key_content_text.config(state="disabled")

        # --- Right Frame: Main Action Buttons ---
        info_button = ttk.Button(right_frame, text="ℹ️ Project Info", command=self.show_project_info)
        info_button.pack(fill="x", pady=(0,10))
        
        self.copy_script_button = ttk.Button(right_frame, text="1. Copy usb_bind_kodi.sh to TV", command=self.copy_script_to_tv)
        self.copy_script_button.pack(fill="x", pady=(0,10))
        self.create_tooltip(self.copy_script_button, "Copies the TV-side script to your LG TV via SSH.\nThis script detects and mounts USB drives for Kodi.")

        self.create_local_script_button = ttk.Button(right_frame, text="2. Create local kodi_usb_binder.sh", command=self.create_local_script)
        self.create_local_script_button.pack(fill="x", pady=(0,10))
        self.create_tooltip(self.create_local_script_button, "Creates a macOS monitoring script that watches your TV.\nRuns every 15 seconds and auto-mounts USB when TV comes online.")

        self.create_autostart_button = ttk.Button(right_frame, text="3. Create macOS AutoStart Service", command=self.create_and_copy_autostart)
        self.create_autostart_button.pack(fill="x")
        self.create_tooltip(self.create_autostart_button, "Sets up automatic startup service for macOS.\nThe monitoring script will run in background after Mac reboots.")

        # Initially disable right-side buttons until setup is done
        self.set_main_buttons_state("disabled")

        # --- Bottom Frame: Terminal Output & Remove Button ---
        remove_frame = ttk.Frame(self)
        remove_frame.pack(side="bottom", fill="x", padx=10, pady=(10,0))
        
        self.remove_all_button = ttk.Button(remove_frame, text="🗑️ Remove All Scripts", command=self.remove_all_scripts)
        self.remove_all_button.pack(side="right", padx=(0,10))
        self.create_remove_tooltip(self.remove_all_button)

        ttk.Label(bottom_frame, text="Terminal Output:").pack(anchor="w")
        self.terminal_text = tk.Text(bottom_frame, height=10, wrap="none", bg="black", fg="#00FF00", insertbackground="white")
        self.terminal_text.pack(fill="both", expand=True)
        self.terminal_text.config(state="disabled")


    def set_main_buttons_state(self, state):
        """Sets the state of the main action buttons on the right."""
        self.copy_script_button.config(state=state)
        self.create_local_script_button.config(state=state)
        self.create_autostart_button.config(state=state)

    def on_main_window_close(self):
        """Handles closing the main window."""
        # Check if the modal window exists and is still active
        if hasattr(self, 'modal_window') and self.modal_window.winfo_exists():
            messagebox.showwarning("Warning", "Please close the 'First Time Setup' window first by clicking 'Continue to App' or its close button.")
        else:
            self.destroy() # Safely close the main application

    def show_first_run_modal(self):
        self.modal_window = tk.Toplevel(self)
        self.modal_window.title("First Time Setup: Essential Steps!")
        # Increased initial size but also made resizable
        self.modal_window.geometry("700x850") # <-- Magasság növelve ide
        self.modal_window.transient(self) # Makes modal dependent on parent window
        self.modal_window.grab_set()      # Disables interaction with parent window
        self.modal_window.resizable(True, True) # Made resizable
        # IMPORTANT: Use the modified on_modal_close_attempt that allows closing
        self.modal_window.protocol("WM_DELETE_WINDOW", self.on_modal_close_attempt)

        modal_frame = ttk.Frame(self.modal_window, padding="15")
        modal_frame.pack(fill="both", expand=True)

        # Use a Canvas with a scrollbar for content in the modal
        canvas = tk.Canvas(modal_frame)
        scrollbar = ttk.Scrollbar(modal_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # --- Content inside the scrollable_frame ---
        ttk.Label(scrollable_frame, text="Welcome to Kodi USB Binder Manager!", font=("Helvetica", 14, "bold")).pack(pady=10)
        ttk.Label(scrollable_frame, text="Before you can automate USB binding, we need to set up a secure connection to your LG TV. Please follow these ONE-TIME steps:", wraplength=650).pack(pady=5)

        # --- TV IP Input (New in Modal) ---
        ttk.Label(scrollable_frame, text="Please enter your LG TV's IP Address:").pack(anchor="w", pady=(0,5))
        self.modal_tv_ip_entry = ttk.Entry(scrollable_frame, textvariable=self.tv_ip, width=25)
        self.modal_tv_ip_entry.pack(anchor="w", pady=(0,10))
        
        ttk.Label(scrollable_frame, text="💡 How to find your TV's IP address:", font=("Helvetica", 10, "bold")).pack(anchor="w", pady=(5,0))
        ttk.Label(scrollable_frame, text="On your LG TV, go to: Settings (⚙️) -> All Settings -> Network -> Wired Connection / Wi-Fi Connection. The IP address will be displayed there (e.g., 192.168.1.74).", wraplength=650).pack(anchor="w", pady=(0,5))
        
        ttk.Separator(scrollable_frame, orient="horizontal").pack(fill="x", pady=10)


        # --- Step 1: Generate SSH Key ---
        ttk.Label(scrollable_frame, text="1. Generate Your SSH Key:", font=("Helvetica", 12, "bold")).pack(anchor="w", pady=(15,5))
        ttk.Label(scrollable_frame, text="This creates a secure, unique key on your Mac for authentication.", wraplength=650).pack(anchor="w")
        
        generate_frame = ttk.Frame(scrollable_frame)
        generate_frame.pack(anchor="w", pady=5)
        self.modal_gen_key_button = ttk.Button(generate_frame, text="Generate New SSH Key", command=self._modal_generate_ssh_key)
        self.modal_gen_key_button.pack(side="left")
        self.key_gen_status = ttk.Label(generate_frame, text=" ❌ Not generated", foreground="red")
        self.key_gen_status.pack(side="left", padx=10)

        # --- Step 2: Copy Key to TV ---
        ttk.Label(scrollable_frame, text="2. Authorize Your Key on the TV (One-Time using 'alpine' password):", font=("Helvetica", 12, "bold")).pack(anchor="w", pady=(15,5))
        ttk.Label(scrollable_frame, text="The first time you connect, your LG TV (if rooted) will ask for a password. The default is 'alpine'. This step uploads your unique key to the TV so you won't need the password again.", wraplength=650).pack(anchor="w")
        
        ttk.Label(scrollable_frame, text="a) Ensure TV IP is entered above.", wraplength=650).pack(anchor="w", pady=(5,2)) # Updated text
        ttk.Label(scrollable_frame, text="b) Copy the command below:", wraplength=650).pack(anchor="w", pady=(5,2))

        ssh_cmd_frame = ttk.Frame(scrollable_frame)
        ssh_cmd_frame.pack(fill="x", pady=5)
        self.ssh_copy_command_text = tk.Text(ssh_cmd_frame, height=2, wrap="word", bg="black", fg="white", font=("Monaco", 10)) # <-- Háttér és betűszín módosítva ide
        self.ssh_copy_command_text.pack(side="left", fill="x", expand=True)
        self.ssh_copy_command_text.config(state="disabled") # Disabled by default
        
        self.copy_cmd_button = ttk.Button(ssh_cmd_frame, text="Copy Command", command=self._copy_ssh_command)
        self.copy_cmd_button.pack(side="left", padx=(5,0))
        self.copy_cmd_button.config(state="disabled") # Disabled until key generated

        ttk.Label(scrollable_frame, text="c) Open your Mac's Terminal app (Search 'Terminal' in Spotlight: ⌘+Space).", wraplength=650).pack(anchor="w", pady=(5,2))
        ttk.Label(scrollable_frame, text="d) Paste the command into the Terminal and press Enter.", wraplength=650).pack(anchor="w")
        
        # MODIFIED: Changed style of the "alpine" password instruction
        self.modal_alpine_warning = ttk.Label(scrollable_frame, 
                                              text="e) When prompted 'password:', type 'alpine' (you won't see anything as you type!). Press Enter. Close Terminal when done.", 
                                              wraplength=650, 
                                              style="Red.TLabel") # Apply the new style
        self.modal_alpine_warning.pack(anchor="w", pady=(5,10))

        # --- Step 3: Test SSH Connection ---
        ttk.Label(scrollable_frame, text="3. Test SSH Connection:", font=("Helvetica", 12, "bold")).pack(anchor="w", pady=(15,5))
        ttk.Label(scrollable_frame, text="Confirm that the password-less SSH connection now works.", wraplength=650).pack(anchor="w")
        
        test_frame = ttk.Frame(scrollable_frame)
        test_frame.pack(anchor="w", pady=5)
        self.modal_test_ssh_button = ttk.Button(test_frame, text="Test SSH Connection", command=self._modal_test_ssh_connection)
        self.modal_test_ssh_button.pack(side="left")
        self.ssh_test_status = ttk.Label(test_frame, text=" ❌ Not tested", foreground="red")
        self.ssh_test_status.pack(side="left", padx=10)
        self.modal_test_ssh_button.config(state="disabled") # Disabled until key generated

        # --- Continue Button ---
        ttk.Separator(scrollable_frame, orient="horizontal").pack(fill="x", pady=10)
        self.continue_button = ttk.Button(scrollable_frame, text="Continue to App", command=self._close_modal_and_enable_main)
        self.continue_button.pack(pady=10)
        self.continue_button.config(state="disabled") # Disabled until all steps completed

        self.update_modal_state() # Initial state update

    def update_modal_state(self):
        """Updates the state of buttons and labels in the modal based on progress."""
        # Step 1 status
        if self.key_generated:
            self.modal_gen_key_button.config(state="disabled")
            self.key_gen_status.config(text=" ✅ Generated!", foreground="green")
            self.copy_cmd_button.config(state="normal")
            self.modal_test_ssh_button.config(state="normal")
            self.generate_ssh_copy_command() # Update command when key path is available
        else:
            self.modal_gen_key_button.config(state="normal")
            self.key_gen_status.config(text=" ❌ Not generated", foreground="red")
            self.copy_cmd_button.config(state="disabled")
            self.modal_test_ssh_button.config(state="disabled")

        # Step 3 status
        if self.ssh_test_successful:
            self.modal_test_ssh_button.config(state="disabled")
            self.ssh_test_status.config(text=" ✅ Successful!", foreground="green")
            self.continue_button.config(state="normal")
        else:
            self.ssh_test_status.config(text=" ❌ Not tested", foreground="red")
            # Only enable test if key is present AND IP is valid
            if self.key_generated and self.validate_ip_address(self.tv_ip.get().strip()):
                self.modal_test_ssh_button.config(state="normal")
            else:
                self.modal_test_ssh_button.config(state="disabled")


    def _modal_generate_ssh_key(self):
        """Wrapper for generate_ssh_key, updates modal state."""
        self.generate_ssh_key() # Call existing method
        # The generate_ssh_key method calls load_ssh_key_content which sets self.ssh_key_path
        # We need to set key_generated after successful generation
        
        # This part should ideally be called after the thread finishes in generate_ssh_key
        # For this example, we'll assume it's successful for immediate UI update.
        # In a real app, you'd have a callback from the thread.
        self.after(500, self._check_key_gen_completion) # Check after a short delay

    def _check_key_gen_completion(self):
        if os.path.exists(self.ssh_key_path.get()) and self.ssh_key_path.get() != "":
            self.key_generated = True
            self.update_modal_state()
        else:
            # Handle error case, e.g., show an error message in modal or terminal
            pass

    def _copy_ssh_command(self):
        """Copies the generated ssh-copy-id command to clipboard."""
        command = self.ssh_copy_command_text.get("1.0", "end").strip()
        if command:
            self.clipboard_clear()
            self.clipboard_append(command)
            messagebox.showinfo("Copied!", "Command copied to clipboard. Now paste it into your Mac's Terminal app.")
        else:
            messagebox.showerror("Error", "No command to copy. Ensure SSH key is generated and TV IP is set.")

    def generate_ssh_copy_command(self):
        """Generates and displays the ssh-copy-id command."""
        tv_ip = self.tv_ip.get().strip()
        ssh_key = self.ssh_key_path.get().strip()
        
        if tv_ip and ssh_key:
            # IMPORTANT: ssh-copy-id expects the public key, so add .pub
            command = f"ssh-copy-id -i \"{ssh_key}.pub\" root@{tv_ip}" 
            self.ssh_copy_command_text.config(state="normal")
            self.ssh_copy_command_text.delete("1.0", "end")
            self.ssh_copy_command_text.insert("1.0", command)
            self.ssh_copy_command_text.config(state="disabled")
            self.copy_cmd_button.config(state="normal")
        else:
            self.ssh_copy_command_text.config(state="normal")
            self.ssh_copy_command_text.delete("1.0", "end")
            self.ssh_copy_command_text.insert("1.0", "Enter TV IP and generate key to see command.")
            self.ssh_copy_command_text.config(state="disabled")
            self.copy_cmd_button.config(state="disabled")


    def _modal_test_ssh_connection(self):
        """Wrapper for test_ssh_connection, updates modal state based on result."""
        ip = self.tv_ip.get().strip()
        key = self.ssh_key_path.get().strip()
        
        if not ip:
            messagebox.showerror("Error", "Please enter the TV IP address in the main window (top left).") # Adjusted message
            return
        if not self.validate_ip_address(ip): # Validate IP here too
            messagebox.showerror("Error", "Please enter a valid IP address in the main window (top left).")
            return
        if not key:
            messagebox.showerror("Error", "Please generate/select SSH private key.")
            return

        # Run the actual test SSH in a thread
        def run_test():
            self.append_terminal(f"Testing SSH connection to {ip} from modal...")
            # The 'alpine' hint is in the modal instructions, so less critical here, but can remain if useful for logs.
            # self.append_terminal("💡 Remember: First time connection needs 'alpine' password in your Mac's TERMINAL!")
            try:
                # Use a simple command to test connection without requiring output beyond success
                cmd = f'ssh -i "{key}" -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=yes root@{ip} "echo SSH_TEST_OK"'
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                if "SSH_TEST_OK" in output:
                    self.append_terminal("SSH connection successful!")
                    self.ssh_test_successful = True
                else:
                    self.append_terminal("SSH connection failed or unexpected output.")
                    self.ssh_test_successful = False
                self.append_terminal(output.strip())
            except subprocess.CalledProcessError as e:
                error_output = e.output if hasattr(e, 'output') and e.output else str(e)
                self.append_terminal(f"SSH connection failed: {error_output.strip()}")
                # Direct the user to the manual step if permission denied
                if "Permission denied" in error_output or "Authenticaton failed" in error_output:
                     messagebox.showerror("SSH Test Failed", 
                         "SSH connection failed! This usually means your key isn't authorized on the TV yet.\n"
                         "Please ensure you've copied the command and entered the 'alpine' password in your Mac's **Terminal** app as instructed in Step 2. Then try 'Test SSH Connection' again.")
            except Exception as e:
                self.append_terminal(f"An unexpected error occurred during SSH test: {e}")
                self.ssh_test_successful = False
            finally:
                self.update_modal_state()

        threading.Thread(target=run_test, daemon=True).start()

    def _close_modal_and_enable_main(self):
        """Closes the modal and enables the main app's action buttons."""
        self.initial_setup_completed = True # Mark setup as complete
        self.modal_window.grab_release()
        self.modal_window.destroy()
        self.set_main_buttons_state("normal")
        messagebox.showinfo("Setup Complete!", "Initial setup is complete! You can now proceed with steps 1, 2, and 3 on the main application window.")

    def on_modal_close_attempt(self):
        """
        Handles attempts to close the modal directly.
        Allows closing even if setup isn't complete, but warns the user.
        """
        if not (self.key_generated and self.ssh_test_successful):
            # Show a warning if critical steps are not completed
            response = messagebox.askokcancel("Warning", "The essential setup steps are not yet completed. If you close this window now, some features of the main application may not work correctly until setup is done. Are you sure you want to close without completing setup?")
            if response:
                self.modal_window.grab_release()
                self.modal_window.destroy()
                self.set_main_buttons_state("disabled") # Keep disabled if setup not complete
        else:
            # If setup is complete, close normally and enable main buttons
            self._close_modal_and_enable_main()


    # --- Original Methods (Modified where necessary for integration) ---

    def validate_ip_address(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def validate_ssh_key(self, key_path):
        if not os.path.isfile(key_path):
            return False, "SSH private key file not found."
        
        try:
            with open(key_path, 'r') as f:
                content = f.read()
                if not (content.startswith('-----BEGIN') or 'PRIVATE KEY' in content):
                    return False, "File doesn't appear to be a valid SSH private key."
            return True, "SSH key is valid."
        except Exception as e:
            return False, f"Error reading SSH key: {str(e)}"

    def append_terminal(self, text):
        self.terminal_text.config(state="normal")
        self.terminal_text.insert("end", text + "\n")
        self.terminal_text.see("end")
        self.terminal_text.config(state="disabled")

    def run_command_thread(self, cmd, success_msg=None, error_msg=None):
        def run():
            self.append_terminal(f"$ {cmd}")
            try:
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                self.append_terminal(output.strip())
                if success_msg:
                    self.append_terminal(success_msg)
            except subprocess.CalledProcessError as e:
                error_output = e.output if hasattr(e, 'output') and e.output else str(e)
                self.append_terminal(f"Error: {error_output.strip()}")
                if error_msg:
                    self.append_terminal(error_msg)
            finally:
                # After any command run, ensure modal state is updated if applicable
                if hasattr(self, 'modal_window') and self.modal_window.winfo_exists():
                    self.update_modal_state()

        threading.Thread(target=run, daemon=True).start()

    def ping_tv(self):
        ip = self.tv_ip.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please enter the TV IP address.")
            return
        
        if not self.validate_ip_address(ip):
            messagebox.showerror("Error", "Please enter a valid IP address.")
            return
            
        cmd = f"ping -c 3 {ip}"
        self.run_command_thread(cmd)

    def test_ssh_connection(self):
        """SSH connection test for the main window (after modal setup)."""
        ip = self.tv_ip.get().strip()
        key = self.ssh_key_path.get().strip()
        
        if not ip:
            messagebox.showerror("Error", "Please enter the TV IP address.")
            return
            
        if not self.validate_ip_address(ip):
            messagebox.showerror("Error", "Please enter a valid IP address.")
            return
            
        if not key:
            messagebox.showerror("Error", "Please select SSH private key.")
            return
            
        is_valid, msg = self.validate_ssh_key(key)
        if not is_valid:
            messagebox.showerror("Error", msg)
            return
        
        # -o BatchMode=yes added to prevent hanging if key fails after setup (e.g., TV re-imaged)
        cmd = f'ssh -i "{key}" -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=yes root@{ip} "echo SSH Connection OK"'
        
        def test_thread():
            self.append_terminal(f"Testing SSH connection to {ip}...")
            try:
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                if "SSH Connection OK" in output: # Check for the expected output
                    self.append_terminal("SSH connection successful!")
                else:
                    self.append_terminal("SSH connection failed or unexpected response.")
                self.append_terminal(output.strip())
            except subprocess.CalledProcessError as e:
                error_output = e.output if hasattr(e, 'output') and e.output else str(e)
                self.append_terminal(f"SSH connection failed: {error_output.strip()}")
                # You might add a hint here to re-check the key setup if it fails unexpectedly
                
        threading.Thread(target=test_thread, daemon=True).start()


    def browse_ssh_key(self):
        path = filedialog.askopenfilename(title="Select SSH Private Key",
                                         filetypes=[("Private key files", "*"), ("All files", "*.*")])
        if path:
            is_valid, msg = self.validate_ssh_key(path)
            if is_valid:
                self.ssh_key_path.set(path)
                self.load_ssh_key_content(path)
                self.key_generated = True # Assume user picked a valid key, so it's "generated" for setup purposes
                if hasattr(self, 'modal_window') and self.modal_window.winfo_exists():
                    self.update_modal_state()
            else:
                messagebox.showerror("Error", f"Invalid SSH key selected:\n{msg}")

    def load_ssh_key_content(self, path):
        try:
            with open(path, "r") as f:
                content = f.read()
            self.key_content_text.config(state="normal")
            self.key_content_text.delete("1.0", "end")
            self.key_content_text.insert("1.0", content)
            self.key_content_text.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Error", f"Cannot read the selected key:\n{e}")

    def generate_ssh_key(self):
        home = os.path.expanduser("~")
        ssh_dir = os.path.join(home, ".ssh")
        os.makedirs(ssh_dir, exist_ok=True)
        suffix = ''.join(random.choice('0123456789abcdef') for _ in range(6))
        key_path = os.path.join(ssh_dir, f"id_ed25519_{suffix}")
        cmd = f'ssh-keygen -t ed25519 -f "{key_path}" -N "" -q'
        
        def gen_key_thread():
            self.append_terminal(f"Generating new SSH key at {key_path} ...")
            try:
                subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                self.append_terminal("SSH key generated successfully.")
                self.ssh_key_path.set(key_path)
                self.load_ssh_key_content(key_path)
                self.key_generated = True # Set flag upon successful generation
            except subprocess.CalledProcessError as e:
                error_output = e.output if hasattr(e, 'output') and e.output else str(e)
                self.append_terminal("Error generating SSH key:")
                self.append_terminal(error_output)
                messagebox.showerror("Error", "Failed to generate SSH key. Check terminal output.")
                self.key_generated = False # Ensure flag is false if failed
            finally:
                if hasattr(self, 'modal_window') and self.modal_window.winfo_exists():
                    self.update_modal_state()

        threading.Thread(target=gen_key_thread, daemon=True).start()

    def copy_script_to_tv(self):
        ip = self.tv_ip.get().strip()
        key = self.ssh_key_path.get().strip()
        
        if not ip or not key:
            messagebox.showerror("Error", "Please provide TV IP and SSH private key path.")
            return
            
        if not self.validate_ip_address(ip):
            messagebox.showerror("Error", "Please enter a valid IP address.")
            return
            
        is_valid, msg = self.validate_ssh_key(key)
        if not is_valid:
            messagebox.showerror("Error", msg)
            return
            
        local_script_path = os.path.join(os.path.expanduser("~"), "usb_bind_kodi.sh")
        
        try:
            with open(local_script_path, "w") as f:
                f.write(usb_bind_kodi_sh_content) # Use the defined content
            os.chmod(local_script_path, 0o755)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create local TV-side script for copying: {e}")
            self.append_terminal(f"Error creating local TV-side script: {e}")
            return


        cmd = f'scp -i "{key}" -o StrictHostKeyChecking=no "{local_script_path}" root@{ip}:/media/developer/usb_bind_kodi.sh'
        
        def copy_thread():
            self.append_terminal(f"Copying usb_bind_kodi.sh to TV ({ip})...")
            try:
                subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                self.append_terminal("Script copied successfully.")
                chmod_cmd = f'ssh -i "{key}" -o StrictHostKeyChecking=no root@{ip} chmod +x /media/developer/usb_bind_kodi.sh'
                subprocess.check_output(chmod_cmd, shell=True, stderr=subprocess.STDOUT)
                self.append_terminal("Script set executable.")
            except subprocess.CalledProcessError as e:
                error_output = e.output if hasattr(e, 'output') and e.output else str(e)
                self.append_terminal(f"Error copying script or setting permissions:\n{error_output}")
            finally:
                if os.path.exists(local_script_path): # Clean up temp local script
                    os.remove(local_script_path)
        threading.Thread(target=copy_thread, daemon=True).start()

    def create_local_script(self):
        home = os.path.expanduser("~")
        local_path = os.path.join(home, "kodi_usb_binder.sh")
        tv_ip = self.tv_ip.get().strip()
        ssh_key = self.ssh_key_path.get().strip()
        
        if not tv_ip:
            messagebox.showerror("Error", "Please enter the TV IP address first.")
            return
        if not ssh_key:
            messagebox.showerror("Error", "Please generate or select an SSH private key first.")
            return

        # Replace placeholders in the script content
        script_content_final = kodi_usb_binder_sh_content.replace("{TV_IP_PLACEHOLDER}", tv_ip).replace("{SSH_KEY_PLACEHOLDER}", ssh_key)

        try:
            with open(local_path, "w") as f:
                f.write(script_content_final)
            os.chmod(local_path, 0o755)
            self.append_terminal(f"Local kodi_usb_binder.sh script created at:\n{local_path}")
        except Exception as e:
            self.append_terminal(f"Error creating local script:\n{e}")
            messagebox.showerror("Error", f"Failed to create local script:\n{e}")

    def create_and_copy_autostart(self):
        home = os.path.expanduser("~")
        username = os.path.basename(home)
        launch_agents_dir = os.path.join(home, "Library", "LaunchAgents")
        plist_path = os.path.join(launch_agents_dir, "com.user.kodi-usb-binder.plist")
        kodi_script_path = os.path.join(home, "kodi_usb_binder.sh")
        
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.kodi-usb-binder</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>{kodi_script_path}</string>
    </array>
    <key>StartInterval</key>
    <integer>15</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>{home}/kodi_usb_binder_daemon.log</string>
    <key>StandardErrorPath</key>
    <string>{home}/kodi_usb_binder_daemon.log</string>
</dict>
</plist>"""
        
        try:
            os.makedirs(launch_agents_dir, exist_ok=True)
            
            with open(plist_path, "w") as f:
                f.write(plist_content)
            
            self.append_terminal(f"LaunchAgent plist created at:\n{plist_path}")
            self.append_terminal("\nTo enable autostart, run these commands in Terminal:")
            self.append_terminal(f"launchctl load {plist_path}")
            self.append_terminal(f"launchctl start com.user.kodi-usb-binder")
            self.append_terminal("\nTo disable autostart:")
            self.append_terminal(f"launchctl stop com.user.kodi-usb-binder")
            self.append_terminal(f"launchctl unload {plist_path}")
            self.append_terminal("\nThe script will run every 15 seconds after boot.")
            
            self.append_terminal("\nAttempting to load the service automatically...")
            load_cmd = f"launchctl load {plist_path}"
            start_cmd = f"launchctl start com.user.kodi-usb-binder"
            
            def load_service():
                try:
                    subprocess.check_output(load_cmd, shell=True, stderr=subprocess.STDOUT)
                    self.append_terminal("Service loaded successfully!")
                    subprocess.check_output(start_cmd, shell=True, stderr=subprocess.STDOUT)
                    self.append_terminal("Service started successfully!")
                    self.append_terminal("Kodi USB Binder is now running in background.")
                except subprocess.CalledProcessError as e:
                    error_output = e.output if hasattr(e, 'output') and e.output else str(e)
                    self.append_terminal(f"Auto-load failed: {error_output}")
                    self.append_terminal("Please run the commands manually from Terminal.")
            
            threading.Thread(target=load_service, daemon=True).start()
            
        except Exception as e:
            self.append_terminal(f"Error creating autostart configuration:\n{e}")
            messagebox.showerror("Error", f"Failed to create autostart configuration:\n{e}")

    def remove_all_scripts(self):
        result = messagebox.askyesno(
            "Confirm Removal", 
            "This will remove:\n"
            "• Local kodi_usb_binder.sh script\n"
            "• macOS AutoStart service\n"
            "• TV-side script (if TV is online)\n"
            "• All log files\n\n"
            "Are you sure you want to continue?"
        )
        
        if not result:
            return
            
        def remove_thread():
            self.append_terminal("🗑️ Starting removal process...")
            
            home = os.path.expanduser("~")
            removed_files = []
            errors = []
            
            try:
                self.append_terminal("Stopping macOS AutoStart service...")
                stop_cmd = "launchctl stop com.user.kodi-usb-binder"
                subprocess.run(stop_cmd, shell=True, capture_output=True)
                
                unload_cmd = "launchctl unload ~/Library/LaunchAgents/com.user.kodi-usb-binder.plist"
                subprocess.run(unload_cmd, shell=True, capture_output=True)
                
                self.append_terminal("AutoStart service stopped.")
            except Exception as e:
                errors.append(f"Error stopping service: {e}")
            
            plist_path = os.path.join(home, "Library", "LaunchAgents", "com.user.kodi-usb-binder.plist")
            if os.path.exists(plist_path):
                try:
                    os.remove(plist_path)
                    removed_files.append("LaunchAgent plist file")
                    self.append_terminal(f"Removed: {plist_path}")
                except Exception as e:
                    errors.append(f"Error removing plist: {e}")
            
            local_script = os.path.join(home, "kodi_usb_binder.sh")
            if os.path.exists(local_script):
                try:
                    os.remove(local_script)
                    removed_files.append("Local monitoring script")
                    self.append_terminal(f"Removed: {local_script}")
                except Exception as e:
                    errors.append(f"Error removing local script: {e}")
            
            log_files = [
                os.path.join(home, "kodi_usb_binder.log"),
                os.path.join(home, "kodi_usb_binder_daemon.log"),
                os.path.join(home, ".tv_bind_state")
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    try:
                        os.remove(log_file)
                        removed_files.append(os.path.basename(log_file))
                        self.append_terminal(f"Removed: {log_file}")
                    except Exception as e:
                        errors.append(f"Error removing {log_file}: {e}")
            
            ip = self.tv_ip.get().strip()
            key = self.ssh_key_path.get().strip()
            
            tv_script_removed = False
            if ip and key and self.validate_ip_address(ip):
                is_valid, msg = self.validate_ssh_key(key)
                if is_valid:
                    try:
                        self.append_terminal(f"Checking if TV ({ip}) is online...")
                        test_cmd = f'ssh -i "{key}" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{ip} "echo TV_ONLINE"'
                        result = subprocess.run(test_cmd, shell=True, capture_output=True, text=True)
                        
                        if result.returncode == 0 and "TV_ONLINE" in result.stdout:
                            self.append_terminal("TV is online, removing TV-side script...")
                            remove_tv_cmd = f'ssh -i "{key}" -o StrictHostKeyChecking=no root@{ip} "rm -f /media/developer/usb_bind_kodi.sh"'
                            subprocess.run(remove_tv_cmd, shell=True, capture_output=True)
                            removed_files.append("TV-side script")
                            tv_script_removed = True
                            self.append_terminal("TV-side script removed successfully.")
                        else:
                            self.append_terminal("⚠️ TV is not online - TV-side script was not removed.")
                            self.append_terminal("You may need to manually remove /media/developer/usb_bind_kodi.sh from TV later.")
                    except Exception as e:
                        errors.append(f"Error removing TV script: {e}")
                        self.append_terminal(f"Error connecting to TV: {e}")
                else:
                    self.append_terminal("⚠️ Invalid SSH key - TV-side script was not removed.")
            else:
                self.append_terminal("⚠️ No TV IP or SSH key specified - TV-side script was not removed.")
            
            self.append_terminal("\n" + "="*50)
            self.append_terminal("🗑️ REMOVAL SUMMARY")
            self.append_terminal("="*50)
            
            if removed_files:
                self.append_terminal("✅ Successfully removed:")
                for file in removed_files:
                    self.append_terminal(f"    • {file}")
            
            if not tv_script_removed:
                self.append_terminal("\n⚠️ TV-side script status:")
                if not ip:
                    self.append_terminal("    • No TV IP specified")
                elif not key:
                    self.append_terminal("    • No SSH key specified")
                else:
                    self.append_terminal("    • TV was offline or unreachable")
                self.append_terminal("    • You may need to manually remove /media/developer/usb_bind_kodi.sh from TV")
            
            if errors:
                self.append_terminal("\n❌ Errors encountered:")
                for error in errors:
                    self.append_terminal(f"    • {error}")
            
            self.append_terminal("\n✅ Local cleanup completed!")
            self.append_terminal("The Kodi USB Binder system has been removed from this Mac.")
            
        threading.Thread(target=remove_thread, daemon=True).start()

    def show_project_info(self):
        info_text = """⚠️ IMPORTANT WARNINGS ⚠️

🔴 ROOTED LG TV REQUIRED
This software ONLY works with ROOTED LG webOS TVs!
Your TV must have SSH access enabled and root privileges.
Standard/unmodified LG TVs will NOT work with this tool.

🔴 ONE-TIME USE SOFTWARE
This is a setup tool that you use ONCE to configure the system.
After completing all 3 steps, you can delete this application.
The automated USB mounting will continue working without it.

═══════════════════════════════════════════════════════════

🎬 KODI USB BINDER MANAGER

WHAT IS THIS PROJECT?
This application automates USB media mounting for Kodi running on LG webOS TVs.

THE PROBLEM:
• LG webOS TVs don't automatically mount USB drives for Kodi
• Users must manually SSH into TV and run mount commands
• USB drives become inaccessible when TV restarts or goes to sleep

THE SOLUTION:
This manager creates an automated system with 3 components:

1️⃣ TV-SIDE SCRIPT (usb_bind_kodi.sh)
    • Runs on the LG TV via SSH
    • Detects USB drives and supported media files
    • Mounts USB partitions to Kodi's media directory
    • Handles cleanup of stale mounts

2️⃣ MACOS MONITORING SCRIPT (kodi_usb_binder.sh)
    • Runs on your Mac in background
    • Monitors TV availability every 15 seconds
    • Automatically triggers USB mounting when TV comes online
    • State-based operation (only acts on changes)
    • Maintains logs with rotation

3️⃣ AUTOSTART SERVICE (LaunchAgent)
    • macOS system service for automatic startup
    • Ensures monitoring runs after Mac reboots
    • Background operation without user intervention

WORKFLOW:
Mac detects TV → SSH connects → Runs USB mount script → Media available in Kodi

SUPPORTED MEDIA:
MP4, MKV, AVI, MOV, MP3, FLAC, JPG, PNG files

REQUIREMENTS:
• ROOTED LG webOS TV with SSH access enabled
• macOS computer on same network
• SSH key pair for authentication
• Kodi installed on TV

⚠️ FIRST TIME SETUP:
The first SSH connection to your LG TV will prompt for a password.
Default password is: alpine

After first connection, you can set up SSH key authentication 
to avoid password prompts in future connections.

💡 AFTER SETUP COMPLETION:
Once you've completed all 3 steps and verified everything works,
you can safely delete this application. The monitoring system
will continue running automatically in the background.
        """
        
        info_window = tk.Toplevel(self)
        info_window.title("Project Information")
        info_window.geometry("800x700")
        info_window.resizable(True, True)
        
        text_frame = ttk.Frame(info_window)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        info_text_widget = tk.Text(text_frame, wrap="word", font=("Monaco", 11))
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=info_text_widget.yview)
        info_text_widget.configure(yscrollcommand=scrollbar.set)
        
        info_text_widget.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        info_text_widget.insert("1.0", info_text)
        
        info_text_widget.config(state="normal")
        
        info_text_widget.tag_configure("warning_highlight", background="#FF4444", foreground="white", font=("Monaco", 12, "bold"))
        info_text_widget.tag_configure("rooted_highlight", background="#FF6B6B", foreground="white", font=("Monaco", 11, "bold"))
        info_text_widget.tag_configure("once_highlight", background="#FFA500", foreground="white", font=("Monaco", 11, "bold"))
        info_text_widget.tag_configure("alpine_highlight", background="#FFFF00", foreground="black", font=("Monaco", 11, "bold"))
        
        content = info_text_widget.get("1.0", "end")
        
        warning_phrases = ["⚠️ IMPORTANT WARNINGS ⚠️", "🔴 ROOTED LG TV REQUIRED", "🔴 ONE-TIME USE SOFTWARE"]
        for phrase in warning_phrases:
            start_pos = content.find(phrase)
            if start_pos != -1:
                lines_before = content[:start_pos].count('\n')
                if lines_before == 0:
                    char_pos = start_pos
                else:
                    last_newline = content.rfind('\n', 0, start_pos)
                    char_pos = start_pos - last_newline - 1
                
                start_idx = f"{lines_before + 1}.{char_pos}"
                end_idx = f"{lines_before + 1}.{char_pos + len(phrase)}"
                info_text_widget.tag_add("warning_highlight", start_idx, end_idx)
        
        rooted_start = content.find("ROOTED LG webOS TVs")
        if rooted_start != -1:
            lines_before = content[:rooted_start].count('\n')
            if lines_before == 0:
                char_pos = rooted_start
            else:
                last_newline = content.rfind('\n', 0, rooted_start)
                char_pos = rooted_start - last_newline - 1
            
            start_idx = f"{lines_before + 1}.{char_pos}"
            end_idx = f"{lines_before + 1}.{char_pos + 19}"
            info_text_widget.tag_add("rooted_highlight", start_idx, end_idx)
        
        once_start = content.find("use ONCE")
        if once_start != -1:
            lines_before = content[:once_start].count('\n')
            if lines_before == 0:
                char_pos = once_start
            else:
                last_newline = content.rfind('\n', 0, once_start)
                char_pos = once_start - last_newline - 1
            
            start_idx = f"{lines_before + 1}.{char_pos}"
            end_idx = f"{lines_before + 1}.{char_pos + 8}"
            info_text_widget.tag_add("once_highlight", start_idx, end_idx)
        
        alpine_start = content.find("alpine")
        if alpine_start != -1:
            lines_before = content[:alpine_start].count('\n')
            if lines_before == 0:
                char_pos = alpine_start
            else:
                last_newline = content.rfind('\n', 0, alpine_start)
                char_pos = alpine_start - last_newline - 1
            
            start_idx = f"{lines_before + 1}.{char_pos}"
            end_idx = f"{lines_before + 1}.{char_pos + 6}"
            info_text_widget.tag_add("alpine_highlight", start_idx, end_idx)

    # --- Tooltips (unchanged from original) ---
    def create_tooltip(self, widget, text):
        tool_tip = ToolTip(widget)
        def enter(event):
            tool_tip.showtip(text)
        def leave(event):
            tool_tip.hidetip()
        widget.bind('<Enter>', enter)
        widget.bind('<Leave>', leave)

    def create_remove_tooltip(self, widget):
        tool_tip = ToolTip(widget)
        def enter(event):
            tool_tip.showtip("Removes all local and TV-side scripts, and macOS autostart services.")
        def leave(event):
            tool_tip.hidetip()
        widget.bind('<Enter>', enter)
        widget.bind('<Leave>', leave)

class ToolTip:
    def __init__(self, widget):
        self.widget = widget
        self.tip_window = None
        self.id = None
        self.x = 0
        self.y = 0

    def showtip(self, text):
        "Display text in tooltip window"
        self.text = text
        if self.tip_window or not self.text:
            return
        x, y, cx, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 25
        y = y + cy + self.widget.winfo_rooty() + 25
        self.tip_window = tk.Toplevel(self.widget)
        self.tip_window.wm_overrideredirect(True)
        self.tip_window.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(self.tip_window, text=self.text, background="#FFFF99", relief="solid", borderwidth=1,
                         font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hidetip(self):
        if self.tip_window:
            self.tip_window.destroy()
        self.tip_window = None

if __name__ == "__main__":
    app = KodiBinderApp()
    app.mainloop()