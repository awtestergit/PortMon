#0x00226000
import ctypes
import struct
import json
# from flask import Flask, jsonify
from threading import Thread, Lock

# Constants
IOCTL_GET_EVENT = 0x00226000  # Replace with the actual IOCTL code
DEVICE_PATH = r"\\.\PortMonDriver"  # Windows device path
EVENT_STRUCT_FORMAT = "QHHIB"  # Matches the driver structure: Timestamp, Protocol, Port, ProcessId, IsAssignment
EVENT_STRUCT_SIZE = struct.calcsize(EVENT_STRUCT_FORMAT)

# Thread-safe event buffer
events_buffer = []
buffer_lock = Lock()

# Open the device handle
def open_device():
    """
    Opens the device file for IOCTL communication on Windows.
    """
    GENERIC_READ = 0x80000000
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80

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
        raise ctypes.WinError(ctypes.get_last_error())
    return handle

# Function to decode event data
def decode_event(data):
    """
    Decode binary event data from the driver.
    """
    unpacked = struct.unpack(EVENT_STRUCT_FORMAT, data)
    return {
        "timestamp": unpacked[0],
        "protocol": unpacked[1],
        "port": unpacked[2],
        "pid": unpacked[3],
        "is_assignment": bool(unpacked[4]),
    }

# Continuous event fetcher
def continuous_event_fetch():
    """
    Continuously fetches events from the kernel driver and adds them to a thread-safe buffer.
    """
    device_handle = open_device()

    while True:
        try:
            # Create a buffer for the output data
            output_buffer = ctypes.create_string_buffer(EVENT_STRUCT_SIZE)

            # Perform blocking IOCTL call
            bytes_returned = ctypes.c_ulong()
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
            if result == 0:  # Check if DeviceIoControl failed
                raise ctypes.WinError(ctypes.get_last_error())

            # Decode the event and add to the buffer
            event = decode_event(output_buffer.raw)
            with buffer_lock:
                events_buffer.append(event)
            print(f"Fetched event: {event}")
        except Exception as e:
            print(f"Error fetching event: {e}")
            continue

    # Close the device handle
    ctypes.windll.kernel32.CloseHandle(device_handle)

# Flask API setup
# app = Flask(__name__)

# @app.route("/api/events", methods=["GET"])
# def get_events():
#     """
#     API endpoint to return buffered events.
#     """
#     with buffer_lock:
#         return jsonify(events_buffer)

if __name__ == "__main__":
    # Start the fetch thread
    fetch_thread = Thread(target=continuous_event_fetch, daemon=True)
    fetch_thread.start()

    # Wait for the fetch_thread to finish
    fetch_thread.join()
    print("Thread has completed. Exiting main program.")

    #app.run(host="0.0.0.0", port=5000)

