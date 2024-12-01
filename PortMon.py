import ctypes
import struct
import signal
import sys
import threading
import time

# Windows API constants
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
ERROR_IO_PENDING = 0x3E5
ERROR_NO_DATA = 0xE8  # No data available

# Constants from the original code
IOCTL_GET_EVENT = 0x00226000
DEVICE_PATH = r"\\.\PortMonDriver"
EVENT_STRUCT_FORMAT = "HHIQQ"
EVENT_STRUCT_SIZE = struct.calcsize(EVENT_STRUCT_FORMAT)

print(f"Event Struct size: {EVENT_STRUCT_SIZE}")

# Thread-safe event buffer
events_buffer = []
buffer_lock = threading.Lock()

# Shared event for signaling thread termination
stop_event = threading.Event()

# pulling interval
INTERVAL = 1 # 1 second

def open_device():
    """
    Opens the device file for IOCTL communication on Windows.
    """
    handle = ctypes.windll.kernel32.CreateFileW(
        DEVICE_PATH,
        GENERIC_READ,
        0,  # No sharing
        None,  # No security attributes
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,  # No template file
    )
    if handle == -1:
        error = ctypes.get_last_error()
        raise OSError(f"Failed to open device. Error code: {error}")
    
    print(f"Device handle obtained: {handle}")
    return handle

handle = open_device()

def decode_event(data):
    """
    Decode binary event data from the driver.
    """
    unpacked = struct.unpack(EVENT_STRUCT_FORMAT, data)
    return {
        "protocol": unpacked[0],
        "port": unpacked[1],
        "pid": unpacked[2],
        "timestamp": unpacked[3],
        "is_assignment": bool(unpacked[4]),
    }

def handle_exit(signum, frame):
    global handle
    """
    Signal handler to gracefully exit on Ctrl+C.
    """
    print("\nInterrupt received. Shutting down...")
    stop_event.set()  # Signal the thread to stop

def continuous_event_fetch(device_handle):
    """
    Continuously fetches events from the kernel driver and adds them to a thread-safe buffer.
    """
    try:
        while not stop_event.is_set():
            try:
                # Create a buffer for the output data
                output_buffer = ctypes.create_string_buffer(EVENT_STRUCT_SIZE)
                bytes_returned = ctypes.c_ulong()

                # Perform IOCTL call
                result = ctypes.windll.kernel32.DeviceIoControl(
                    device_handle,
                    IOCTL_GET_EVENT,
                    None,  # No input buffer
                    0,     # Input buffer size
                    output_buffer,  # Output buffer
                    EVENT_STRUCT_SIZE,
                    ctypes.byref(bytes_returned),
                    None,  # No overlapped structure
                )

                if result == 0:
                    error_code = ctypes.get_last_error()
                    
                    # Handle specific error conditions
                    if error_code == ERROR_NO_DATA or error_code == 0:
                        # No data available, wait a bit before retrying
                        # print("no data")
                        time.sleep(INTERVAL)
                        continue
                    elif error_code == ERROR_IO_PENDING:
                        # Operation is pending, wait and retry
                        print("IO pending")
                        time.sleep(INTERVAL)
                        continue
                    else:
                        # Unexpected error
                        print(f"DeviceIoControl error: {error_code}")
                        
                        # Check if we should continue or break
                        if stop_event.is_set():
                            break
                        
                        # Wait before retrying
                        time.sleep(INTERVAL)
                        continue

                # Check if we got any data
                if bytes_returned.value > 0:
                    # Decode the event and add to the buffer
                    event = decode_event(output_buffer.raw)
                    with buffer_lock:
                        events_buffer.append(event)
                    print(f"Fetched event: {event}")
                else:
                    # No data returned, wait briefly
                    print("no data returned to buffer")
                    time.sleep(INTERVAL)

            except Exception as e:
                print(f"Error in event fetching: {e}")
                
                # Check stop condition
                if stop_event.is_set():
                    break
                
                # Prevent tight looping
                time.sleep(INTERVAL)

    except Exception as e:
        print(f"Unexpected error in event fetch thread: {e}")

def main():
    global handle
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, handle_exit)
    
    try:
        # Open device handle
        # handle = open_device()

        # Start the fetch thread
        fetch_thread = threading.Thread(target=continuous_event_fetch, args=[handle], daemon=None)
        fetch_thread.start()

        # Wait for the thread to complete or be interrupted
        while fetch_thread.is_alive():
            fetch_thread.join(timeout=1)

    except Exception as e:
        print(f"Error in main: {e}")
    finally:
        # Ensure the thread is signaled to stop
        stop_event.set()
        
        # Wait a moment for thread to clean up
        time.sleep(0.5)
        ctypes.windll.kernel32.CloseHandle(handle)
        print("Program terminated.")

if __name__ == "__main__":
    main()