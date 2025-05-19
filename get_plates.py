#!/usr/bin/env python3

import time
import sys
from ctypes import c_void_p, cast, POINTER, c_char_p, sizeof # For casting in callback and sizeof

# Attempt to import SDK components. These should be available after installing the .whl package.
# The exact structure names might need adjustment based on the content of SDK_Struct.py and SDK_Enum.py
try:
    from NetSDK.NetSDK import NetClient
    from NetSDK.SDK_Enum import EM_LOGIN_SPAC_CAP_TYPE, EM_EVENT_IVS_TYPE
    from NetSDK.SDK_Struct import NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY
    # Placeholder for the actual ANPR event structure.
    # You'll need to find the correct structure name from SDK_Struct.py for traffic events,
    # e.g., DEV_EVENT_TRAFFICJUNCTION_INFO, NET_A_DEV_EVENT_TRAFFICGATE_INFO, etc.
    # For this example, let's assume a generic structure or one specific like DEV_EVENT_TRAFFICJUNCTION_INFO
    # from Appendix 2 of the NetSDK Python Programming Manual.
    from NetSDK.SDK_Struct import DEV_EVENT_TRAFFICJUNCTION_INFO # Example, verify correct structure from your SDK files
    from NetSDK.SDK_Callback import fDisConnect, fHaveReConnect, fAnalyzerDataCallBack
except ImportError as e:
    print(f"Failed to import Dahua NetSDK modules. Ensure the SDK is installed correctly in your Python environment (venv): {e}")
    print("Please refer to section 1.3.1 of 'NetSDK_Python_Programming Manual.pdf' for installation instructions.")
    sys.exit(1)
except Exception as e:
    print(f"An unexpected error occurred during SDK import: {e}")
    sys.exit(1)

# --- Configuration ---
CAMERA_IP = "10.45.14.11"  # YOUR CAMERA'S IP ADDRESS
CAMERA_PORT = 37777          # Default Dahua TCP port, verify if different for your camera
USERNAME = "admin"           # YOUR CAMERA'S USERNAME
PASSWORD = "%Gq65FUS8842G"   # YOUR CAMERA'S PASSWORD
CHANNEL_ID = 0               # Typically 0 for the first channel of a camera

# ANPR Event Type to subscribe to.
# Common choices from SDK_Enum.EM_EVENT_IVS_TYPE:
#   TRAFFICJUNCTION, TRAFFICGATE, TRAFFICSNAPSHOT, MANUALSNAP
# Refer to Appendix 2 of the NetSDK Python Programming Manual for event types and their structures.
# Using TRAFFICJUNCTION as an example. You might need to change this.
# You can also try EM_EVENT_IVS_TYPE.ALL to receive all intelligent events,
# but then you MUST handle different dwAlarmType values and pAlarmInfo structures in the callback.
ANPR_EVENT_TYPE = EM_EVENT_IVS_TYPE.TRAFFICJUNCTION

# --- Global Variables ---
g_sdk = None
g_login_id = 0
g_analyzer_handle = 0

# --- Callback Functions ---
# These functions will be called by the SDK.
# Their signatures are defined by WINFUNCTYPE in SDK_Callback.py.

@fDisConnect # Decorator from SDK_Callback.py
def DisconnectCallback(lLoginID, pchDVRIP, nDVRPort, dwUser):
    ip_address = pchDVRIP.decode('utf-8', errors='ignore') if pchDVRIP else "Unknown IP"
    print(f"--- Camera Disconnected ---")
    print(f"  LoginID: {lLoginID}")
    print(f"  Device IP: {ip_address}:{nDVRPort}")
    print(f"  User Data: {dwUser}")
    print(f"---------------------------\n")
    # Consider setting a flag here to attempt reconnection in the main loop or to exit gracefully.

@fHaveReConnect # Decorator from SDK_Callback.py
def ReconnectCallback(lLoginID, pchDVRIP, nDVRPort, dwUser):
    ip_address = pchDVRIP.decode('utf-8', errors='ignore') if pchDVRIP else "Unknown IP"
    print(f"--- Camera Reconnected ---")
    print(f"  LoginID: {lLoginID}")
    print(f"  Device IP: {ip_address}:{nDVRPort}")
    print(f"  User Data: {dwUser}")
    print(f"--------------------------\n")

@fAnalyzerDataCallBack # Decorator from SDK_Callback.py
def AnalyzerDataCallback(lAnalyzerHandle, dwAlarmType, pAlarmInfo, pBuffer, dwBufSize, dwUser, nSequence, reserved):
    """
    Callback function to process intelligent traffic events (including ANPR).
    Signature from Section 4.8, NetSDK_Python_Programming Manual.pdf
    """
    global g_login_id # If needed for any SDK calls from callback, though generally not recommended
    print(f"--- Intelligent Event Received ---")
    print(f"  AnalyzerHandle: {lAnalyzerHandle}")
    print(f"  AlarmType: {dwAlarmType} (Refer to EM_EVENT_IVS_TYPE in SDK_Enum.py)")
    print(f"  Sequence: {nSequence}")

    # IMPORTANT: pAlarmInfo needs to be cast to the correct structure based on dwAlarmType.
    # The manual (Appendix 2) lists event types and their corresponding C structures.
    # You need to find the Python equivalent in your SDK_Struct.py.

    if dwAlarmType == EM_EVENT_IVS_TYPE.TRAFFICJUNCTION:
        try:
            # Ensure DEV_EVENT_TRAFFICJUNCTION_INFO is the correct structure name from your SDK's SDK_Struct.py
            event_info = cast(pAlarmInfo, POINTER(DEV_EVENT_TRAFFICJUNCTION_INFO)).contents
            
            # Extracting information - field names and paths are educated guesses based on typical Dahua SDKs.
            # YOU MUST VERIFY these against your specific SDK_Struct.py file for DEV_EVENT_TRAFFICJUNCTION_INFO.
            
            plate_number = "N/A"
            if hasattr(event_info, 'stuObject') and hasattr(event_info.stuObject, 'szText'):
                 # Assuming szText is a byte array for plate number
                plate_number = event_info.stuObject.szText.decode('utf-8', errors='ignore').strip('\x00').strip()

            timestamp_str = "N/A"
            if hasattr(event_info, 'UTC') and hasattr(event_info.UTC, 'dwYear'): # Assuming UTC is a common time structure like NET_TIME
                utc = event_info.UTC
                timestamp_str = f"{utc.dwYear:04d}-{utc.dwMonth:02d}-{utc.dwDay:02d} " + \
                                f"{utc.dwHour:02d}:{utc.dwMinute:02d}:{utc.dwSecond:02d}"

            vehicle_color_enum = "N/A"
            plate_color_enum = "N/A"
            vehicle_type_enum = "N/A"

            if hasattr(event_info, 'stuVehicle'):
                if hasattr(event_info.stuVehicle, 'emColor'):
                    vehicle_color_enum = event_info.stuVehicle.emColor # This will be an enum value
                if hasattr(event_info.stuVehicle, 'emVehicleType'): # Check correct attribute name
                    vehicle_type_enum = event_info.stuVehicle.emVehicleType # This will be an enum value
            
            if hasattr(event_info, 'stuObject') and hasattr(event_info.stuObject, 'emPlateColor'): # Check correct attribute name
                 plate_color_enum = event_info.stuObject.emPlateColor # This will be an enum value

            print(f"  Event Type Details: TRAFFICJUNCTION")
            print(f"    Plate Number: {plate_number}")
            print(f"    Timestamp: {timestamp_str}")
            print(f"    Vehicle Color Enum: {vehicle_color_enum}") # Map enum to string if needed
            print(f"    Plate Color Enum: {plate_color_enum}")     # Map enum to string if needed
            print(f"    Vehicle Type Enum: {vehicle_type_enum}")   # Map enum to string if needed

            # Image data is in pBuffer with size dwBufSize
            if pBuffer and dwBufSize > 0:
                print(f"    Image data size: {dwBufSize} bytes received.")
                # Example: save image (ensure you have write permissions in the script's directory)
                # image_filename = f"plate_{plate_number if plate_number != 'N/A' else 'UNKNOWN'}_{int(time.time())}.jpg"
                # try:
                #     # pBuffer is a POINTER(c_ubyte). To get bytes: ctypes.string_at(pBuffer, dwBufSize)
                #     image_bytes = string_at(pBuffer, dwBufSize) # Requires: from ctypes import string_at
                #     with open(image_filename, "wb") as img_file:
                #         img_file.write(image_bytes)
                #     print(f"    Image saved as {image_filename}")
                # except Exception as img_e:
                #     print(f"    Error saving image: {img_e}")
            else:
                print(f"    No image data in this event.")

        except AttributeError as ae:
            print(f"  AttributeError processing TRAFFICJUNCTION: {ae}. Field names might be incorrect for your SDK_Struct.py version.")
        except Exception as e:
            print(f"  Error processing TRAFFICJUNCTION event info: {type(e).__name__} - {e}")
            print(f"  Ensure DEV_EVENT_TRAFFICJUNCTION_INFO structure and its fields are correctly defined/accessed in your SDK files.")

    # elif dwAlarmType == EM_EVENT_IVS_TYPE.TRAFFICGATE: # Example for another event type
    #     try:
    #         # from NetSDK.SDK_Struct import NET_A_DEV_EVENT_TRAFFICGATE_INFO # Verify this struct name
    #         event_info = cast(pAlarmInfo, POINTER(NET_A_DEV_EVENT_TRAFFICGATE_INFO)).contents
    #         # ... process NET_A_DEV_EVENT_TRAFFICGATE_INFO fields, similar to above ...
    #         print(f"  Event Type Details: TRAFFICGATE")
    #         # ...
    #     except Exception as e:
    #         print(f"  Error processing TRAFFICGATE event info: {e}")
            
    else:
        print(f"  Received unhandled or unknown event type: {dwAlarmType}. pAlarmInfo might need specific casting and handling.")

    print(f"----------------------------------\n")
    # Callback should return quickly. For long processing, consider using a queue and a separate thread.


def main():
    global g_sdk, g_login_id, g_analyzer_handle

    print("Initializing Dahua NetSDK...")
    g_sdk = NetClient() # Create NetClient instance
    
    # Initialize SDK (Section 2.1.4, 3.1.1 of NetSDK Python Programming Manual)
    init_success = g_sdk.InitEx(DisconnectCallback) # Pass the callback function directly
    if not init_success:
        print("Failed to initialize NetSDK. Exiting.")
        # error_code = g_sdk.GetLastError() # If GetLastError is available and provides more info
        # print(f"Error details (if available): {error_code}")
        return

    print("SDK Initialized successfully.")

    # Set Auto Reconnect Callback (Optional, Section 2.1.4, 3.1.3)
    g_sdk.SetAutoReconnect(ReconnectCallback) # Pass the callback function directly
    print("Auto-reconnect callback set.")

    # Login to Device (Section 2.3.4, 3.3.1)
    print(f"Logging into camera: {CAMERA_IP}:{CAMERA_PORT}")
    login_req = NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY()
    login_req.dwSize = sizeof(NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY) # Use ctypes.sizeof
    login_req.szIP = CAMERA_IP.encode('utf-8')
    login_req.nPort = CAMERA_PORT
    login_req.szUserName = USERNAME.encode('utf-8')
    login_req.szPassword = PASSWORD.encode('utf-8')
    login_req.emSpecCap = EM_LOGIN_SPAC_CAP_TYPE.TCP # As per example in manual Section 2.3.4
    login_req.pCapParam = None # As per example in manual

    login_res = NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY()
    login_res.dwSize = sizeof(NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY) # Use ctypes.sizeof

    # LoginWithHighLevelSecurity returns a tuple: (loginID, device_info_struct, error_message_string)
    # as per manual section 2.3.4 Sample Code
    login_result_tuple = g_sdk.LoginWithHighLevelSecurity(login_req, login_res)
    
    if isinstance(login_result_tuple, tuple) and len(login_result_tuple) == 3:
        g_login_id = login_result_tuple[0]
        # device_info_struct_from_tuple = login_result_tuple[1] # This is NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY
        error_msg_str = login_result_tuple[2]
    else:
        # Fallback or error handling if the return type isn't as expected.
        # This case might indicate an issue with the SDK version or function signature.
        print(f"Unexpected login result format: {login_result_tuple}")
        g_login_id = 0 # Assume failure
        error_msg_str = "Unexpected login result format from SDK."

    if g_login_id == 0:
        print(f"Failed to login to camera. SDK Error Message: '{error_msg_str}'")
        print(f"Please check credentials, network connectivity, and camera status.")
        # error_code_from_sdk = login_res.dwError if hasattr(login_res, 'dwError') else "N/A" # Check if error code is in login_res
        # print(f"DeviceLogin Error Code (if available in login_res): {error_code_from_sdk}")
        # last_error = g_sdk.GetLastError() # Check if GetLastError provides more info
        # print(f"GetLastError: {last_error}")
        g_sdk.Cleanup()
        return

    print(f"Login successful. LoginID: {g_login_id}")
    # Example: Accessing device info from the populated login_res structure
    # (field names depend on NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY actual definition in SDK_Struct.py)
    # if hasattr(login_res, 'stuDeviceInfo') and hasattr(login_res.stuDeviceInfo, 'nChanNum'):
    #     print(f"Device Info: Channels={login_res.stuDeviceInfo.nChanNum}, DeviceType={login_res.stuDeviceInfo.byDVRType}")


    # Start Listening for Intelligent Traffic Events (Section 2.10.4, 3.10.1)
    print(f"Subscribing to ANPR events (Type Code: {ANPR_EVENT_TYPE}, Channel: {CHANNEL_ID})...")
    # bNeedPicFile: 1 to subscribe to image, 0 not to. (Manual Section 3.10.1)
    # dwUser: Custom user data to be passed to the callback. Here, 0.
    # reserved: Typically None or 0 unless specified.
    g_analyzer_handle = g_sdk.RealLoadPictureEx(g_login_id, CHANNEL_ID, ANPR_EVENT_TYPE, 1, AnalyzerDataCallback, 0, None)

    if g_analyzer_handle == 0:
        print(f"Failed to subscribe to ANPR events (RealLoadPictureEx returned 0).")
        # last_error = g_sdk.GetLastError() # If available and provides an error code
        # print(f"GetLastError after RealLoadPictureEx: {last_error}")
        g_sdk.Logout(g_login_id)
        g_sdk.Cleanup()
        return

    print(f"Successfully subscribed to ANPR events. AnalyzerHandle: {g_analyzer_handle}")
    print("Waiting for ANPR data... Press Ctrl+C to exit.")

    try:
        while True:
            time.sleep(1)  # Keep the main thread alive to receive callbacks
    except KeyboardInterrupt:
        print("\nCtrl+C pressed. Exiting...")
    except Exception as e:
        print(f"\nAn unexpected error occurred in the main loop: {e}")
    finally:
        # Cleanup (Section 2.10.2, 2.3.2, 2.1.2 - Interface Overview)
        if g_analyzer_handle != 0 and g_sdk:
            print(f"Stopping ANPR event subscription (Handle: {g_analyzer_handle})...")
            result = g_sdk.StopLoadPic(g_analyzer_handle)
            print(f"ANPR subscription stopped." + (" Successfully." if result else " Failed."))
            g_analyzer_handle = 0

        if g_login_id != 0 and g_sdk:
            print(f"Logging out (LoginID: {g_login_id})...")
            result = g_sdk.Logout(g_login_id)
            print(f"Logout " + ("successful." if result else "failed."))
            g_login_id = 0

        if g_sdk:
            print("Cleaning up SDK resources...")
            g_sdk.Cleanup()
            print("SDK Cleanup complete.")
            g_sdk = None

if __name__ == "__main__":
    # Basic check for placeholder credentials - remove if you hardcode them directly
    if "YOUR_CAMERA_IP_ADDRESS" in CAMERA_IP or "YOUR_PASSWORD" in PASSWORD :
         print("ERROR: Please update CAMERA_IP and PASSWORD in the script with actual values before running.")
    else:
        main()
