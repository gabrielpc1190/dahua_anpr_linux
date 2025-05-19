#!/usr/bin/env python3

import time
import sys
import logging
from ctypes import c_void_p, cast, POINTER, c_char_p, sizeof, string_at

# --- SDK Import Block ---
try:
    from NetSDK.NetSDK import NetClient
    from NetSDK.SDK_Enum import EM_LOGIN_SPAC_CAP_TYPE, EM_EVENT_IVS_TYPE
    from NetSDK.SDK_Struct import NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY
    
    # Verified Structures from your SDK_Struct.py
    from NetSDK.SDK_Struct import DEV_EVENT_TRAFFICJUNCTION_INFO
    from NetSDK.SDK_Struct import NET_A_DEV_EVENT_TRAFFICGATE_INFO
    from NetSDK.SDK_Struct import NET_A_DEV_EVENT_TRAFFICSNAPSHOT_INFO
    from NetSDK.SDK_Struct import NET_DEV_EVENT_TRAFFIC_MANUALSNAP_INFO # Re-enabled

    # Common sub-structures that hold ANPR relevant data
    from NetSDK.SDK_Struct import SDK_MSG_OBJECT, NET_A_MSG_OBJECT # For general object data if specific car data isn't available
    from NetSDK.SDK_Struct import DEV_EVENT_TRAFFIC_TRAFFICCAR_INFO # For detailed traffic car info
    from NetSDK.SDK_Struct import NET_TIME_EX # For timestamps

    from NetSDK.SDK_Callback import fDisConnect, fHaveReConnect, fAnalyzerDataCallBack
except ImportError as e:
    print(f"CRITICAL: Failed to import Dahua NetSDK modules. Ensure the SDK is installed correctly: {e}")
    sys.exit(1)
except Exception as e:
    print(f"CRITICAL: An unexpected error occurred during SDK import: {e}")
    sys.exit(1)
# --- End SDK Import Block ---

# --- Configuration ---
CAMERA_IP = "10.45.14.11"
CAMERA_PORT = 37777
USERNAME = "admin"
PASSWORD = "%Gq65FUS8842G"
CHANNEL_ID = 0
ANPR_EVENT_TYPE = EM_EVENT_IVS_TYPE.ALL
LOG_FILE = "anpr_events.log"

# --- Global Variables ---
g_sdk = None
g_login_id = 0
g_analyzer_handle = 0

# --- Logging Setup ---
log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(module)s.%(funcName)s: %(message)s')
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.INFO)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
if not logger.handlers:
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
# --- End Logging Setup ---

# --- Helper Function for ANPR Data Extraction ---
def extract_anpr_details(event_info, event_type_name):
    """
    Extracts ANPR details from a specific event structure.
    `event_info` is the already casted ctypes Structure object.
    """
    plate_number = "N/A"
    timestamp_str = "N/A"
    plate_color_str = "N/A"
    vehicle_color_str = "N/A"
    vehicle_type_str = "N/A" # You might need an enum mapping for this

    try:
        # Timestamp (usually in a 'UTC' field of type NET_TIME_EX)
        if hasattr(event_info, 'UTC') and isinstance(event_info.UTC, NET_TIME_EX):
            utc = event_info.UTC
            timestamp_str = f"{utc.dwYear:04d}-{utc.dwMonth:02d}-{utc.dwDay:02d} " + \
                            f"{utc.dwHour:02d}:{utc.dwMinute:02d}:{utc.dwSecond:02d}"
            if hasattr(utc, 'dwMillisecond'):
                timestamp_str += f".{utc.dwMillisecond:03d}"

        # Prioritize stTrafficCar for detailed info
        if hasattr(event_info, 'stTrafficCar') and isinstance(event_info.stTrafficCar, DEV_EVENT_TRAFFIC_TRAFFICCAR_INFO):
            traffic_car = event_info.stTrafficCar
            if hasattr(traffic_car, 'szPlateNumber'):
                plate_number = traffic_car.szPlateNumber.decode('utf-8', errors='ignore').strip('\x00').strip()
            if hasattr(traffic_car, 'szPlateColor'):
                plate_color_str = traffic_car.szPlateColor.decode('utf-8', errors='ignore').strip('\x00').strip()
            if hasattr(traffic_car, 'szVehicleColor'):
                vehicle_color_str = traffic_car.szVehicleColor.decode('utf-8', errors='ignore').strip('\x00').strip()
            if hasattr(traffic_car, 'emCarType'): # This will be an enum integer
                vehicle_type_str = f"EnumVal:{traffic_car.emCarType}"

        # Fallback to stuObject or stuVehicle if stTrafficCar is not present or plate is still N/A
        if plate_number == "N/A":
            obj_to_check = None
            if hasattr(event_info, 'stuObject'): # SDK_MSG_OBJECT or NET_A_MSG_OBJECT
                obj_to_check = event_info.stuObject
            elif hasattr(event_info, 'stuVehicle'): # SDK_MSG_OBJECT or NET_A_MSG_OBJECT (often used for vehicle body/logo)
                 obj_to_check = event_info.stuVehicle
            
            if obj_to_check and hasattr(obj_to_check, 'szText'):
                # Check if object type suggests it's a plate
                object_type = ""
                if hasattr(obj_to_check, 'szObjectType'):
                    object_type = obj_to_check.szObjectType.decode('utf-8', errors='ignore').strip('\x00').strip().lower()
                
                # Heuristic: if szText is present and object type is not 'logo' or similar, it might be the plate
                if "plate" in object_type or "vehicle" in object_type or object_type == "": # Empty object type might still be plate
                    plate_candidate = obj_to_check.szText.decode('utf-8', errors='ignore').strip('\x00').strip()
                    if plate_candidate: # Ensure it's not an empty string
                        plate_number = plate_candidate
                        # Plate color might be in stuObject.emPlateColor if it's part of a more generic object structure
                        if hasattr(obj_to_check, 'emPlateColor') and plate_color_str == "N/A":
                            plate_color_str = f"EnumVal:{obj_to_check.emPlateColor}"


    except AttributeError as ae:
        logger.error(f"    AttributeError extracting from {event_type_name}: {ae}")
    except Exception as e:
        logger.error(f"    Exception extracting from {event_type_name}: {type(e).__name__} - {e}")
        
    return plate_number, timestamp_str, plate_color_str, vehicle_color_str, vehicle_type_str
# --- End Helper Function ---


# --- Callback Functions ---
@fDisConnect
def DisconnectCallback(lLoginID, pchDVRIP, nDVRPort, dwUser):
    ip_address = pchDVRIP.decode('utf-8', errors='ignore') if pchDVRIP else "Unknown IP"
    logger.warning(f"--- Camera Disconnected --- LoginID: {lLoginID}, Device: {ip_address}:{nDVRPort}, UserData: {dwUser}\n")

@fHaveReConnect
def ReconnectCallback(lLoginID, pchDVRIP, nDVRPort, dwUser):
    ip_address = pchDVRIP.decode('utf-8', errors='ignore') if pchDVRIP else "Unknown IP"
    logger.info(f"--- Camera Reconnected --- LoginID: {lLoginID}, Device: {ip_address}:{nDVRPort}, UserData: {dwUser}\n")

@fAnalyzerDataCallBack
def AnalyzerDataCallback(lAnalyzerHandle, dwAlarmType, pAlarmInfo, pBuffer, dwBufSize, dwUser, nSequence, reserved):
    logger.info(f"--- Intelligent Event Received --- AnalyzerHandle: {lAnalyzerHandle}, AlarmType: {dwAlarmType} (Hex: {hex(dwAlarmType)}), Sequence: {nSequence}")

    plate, event_time, plate_color, vehicle_color, vehicle_type = "N/A", "N/A", "N/A", "N/A", "N/A"
    event_type_str = f"EventTypeRaw({dwAlarmType})"
    processed_anpr = False

    event_handlers = {
        EM_EVENT_IVS_TYPE.TRAFFICJUNCTION: ("TRAFFICJUNCTION", DEV_EVENT_TRAFFICJUNCTION_INFO),
        EM_EVENT_IVS_TYPE.TRAFFICGATE: ("TRAFFICGATE", NET_A_DEV_EVENT_TRAFFICGATE_INFO),
        # NET_A_DEV_EVENT_TRAFFICSNAPSHOT_INFO is complex, needs special handling if used for ANPR
        # EM_EVENT_IVS_TYPE.TRAFFICSNAPSHOT: ("TRAFFICSNAPSHOT", NET_A_DEV_EVENT_TRAFFICSNAPSHOT_INFO),
        EM_EVENT_IVS_TYPE.TRAFFIC_MANUALSNAP: ("TRAFFIC_MANUALSNAP", NET_DEV_EVENT_TRAFFIC_MANUALSNAP_INFO),
    }

    if dwAlarmType in event_handlers:
        event_type_str, StructType = event_handlers[dwAlarmType]
        try:
            event_info_ptr = cast(pAlarmInfo, POINTER(StructType))
            plate, event_time, plate_color, vehicle_color, vehicle_type = extract_anpr_details(event_info_ptr.contents, event_type_str)
            processed_anpr = True
            logger.info(f"  Event Parsed: {event_type_str}")
            logger.info(f"    Plate Number: {plate}")
            logger.info(f"    Timestamp: {event_time}")
            logger.info(f"    Plate Color: {plate_color}")
            logger.info(f"    Vehicle Color: {vehicle_color}")
            logger.info(f"    Vehicle Type: {vehicle_type}")
        except Exception as e:
            logger.error(f"  Error casting or processing {event_type_str}: {e}", exc_info=True)

    elif dwAlarmType == EM_EVENT_IVS_TYPE.TRAFFICSNAPSHOT: # Handle separately due to different structure
        event_type_str = "TRAFFICSNAPSHOT"
        logger.info(f"  Event Type: {event_type_str}. This event aggregates multiple captures. Detailed parsing not implemented in this generic handler.")
        # To parse this, you'd iterate through event_info.stuCarWayInfo and then its sub-structures.
        # event_info_ptr = cast(pAlarmInfo, POINTER(NET_A_DEV_EVENT_TRAFFICSNAPSHOT_INFO))
        # ... custom parsing logic for NET_A_DEV_EVENT_TRAFFICSNAPSHOT_INFO ...
        processed_anpr = False # Or True if you implement parsing

    else:
        logger.info(f"  Event Type {event_type_str} not specifically handled for ANPR details in this script version.")

    if pBuffer and dwBufSize > 0:
        logger.info(f"    Image data size: {dwBufSize} bytes received.")
        # image_filename = f"event_{event_type_str}_{plate if plate not in ['N/A', ''] else 'NO_PLATE'}_{int(time.time())}.jpg"
        # try:
        #     image_bytes = string_at(pBuffer, dwBufSize)
        #     with open(image_filename, "wb") as img_file:
        #         img_file.write(image_bytes)
        #     logger.info(f"    Image saved as {image_filename}")
        # except Exception as img_e:
        #     logger.error(f"    Error saving image: {img_e}")
    else:
        logger.info(f"    No image data in this event.")
    
    logger.info(f"----------------------------------\n")

# --- Main Application Logic ---
def main():
    global g_sdk, g_login_id, g_analyzer_handle
    logger.info("Initializing Dahua NetSDK...")
    g_sdk = NetClient()
    
    init_success = g_sdk.InitEx(DisconnectCallback)
    if not init_success:
        logger.error("Failed to initialize NetSDK. Exiting.")
        return

    logger.info("SDK Initialized successfully.")
    g_sdk.SetAutoReconnect(ReconnectCallback)
    logger.info("Auto-reconnect callback set.")

    logger.info(f"Logging into camera: {CAMERA_IP}:{CAMERA_PORT}")
    login_req = NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY()
    login_req.dwSize = sizeof(NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY)
    login_req.szIP = CAMERA_IP.encode('utf-8')
    login_req.nPort = CAMERA_PORT
    login_req.szUserName = USERNAME.encode('utf-8')
    login_req.szPassword = PASSWORD.encode('utf-8')
    login_req.emSpecCap = EM_LOGIN_SPAC_CAP_TYPE.TCP
    login_req.pCapParam = None
    login_res = NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY()
    login_res.dwSize = sizeof(NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY)
    login_result_tuple = g_sdk.LoginWithHighLevelSecurity(login_req, login_res)
    
    if isinstance(login_result_tuple, tuple) and len(login_result_tuple) == 3:
        g_login_id = login_result_tuple[0]
        error_msg_str = login_result_tuple[2]
    else:
        logger.error(f"Unexpected login result format: {login_result_tuple}")
        g_login_id = 0 
        error_msg_str = "Unexpected login result format from SDK."

    if g_login_id == 0:
        logger.error(f"Failed to login. SDK Message: '{error_msg_str}'. Check credentials/network.")
        if hasattr(g_sdk, 'Cleanup'): g_sdk.Cleanup()
        return
    logger.info(f"Login successful. LoginID: {g_login_id}")

    logger.info(f"Subscribing to ALL IVS events (Type Code: {ANPR_EVENT_TYPE}, Channel: {CHANNEL_ID})...")
    g_analyzer_handle = g_sdk.RealLoadPictureEx(g_login_id, CHANNEL_ID, ANPR_EVENT_TYPE, 1, AnalyzerDataCallback, 0, None)

    if g_analyzer_handle == 0:
        logger.error(f"Failed to subscribe to events (RealLoadPictureEx returned 0).")
        if hasattr(g_sdk, 'Logout'): g_sdk.Logout(g_login_id)
        if hasattr(g_sdk, 'Cleanup'): g_sdk.Cleanup()
        return
    logger.info(f"Successfully subscribed to all IVS events. AnalyzerHandle: {g_analyzer_handle}")
    logger.info("Waiting for ANPR data... Press Ctrl+C to exit.")

    try:
        while True: time.sleep(1)
    except KeyboardInterrupt: logger.info("\nCtrl+C pressed. Exiting...")
    except Exception as e: logger.error(f"\nUnexpected error in main loop: {e}", exc_info=True)
    finally:
        if g_analyzer_handle != 0 and g_sdk and hasattr(g_sdk, 'StopLoadPic'):
            logger.info(f"Stopping event subscription (Handle: {g_analyzer_handle})...")
            res_stop = g_sdk.StopLoadPic(g_analyzer_handle)
            logger.info(f"Event subscription stopped." + (" Successfully." if res_stop else " Failed."))
            g_analyzer_handle = 0

        if g_login_id != 0 and g_sdk and hasattr(g_sdk, 'Logout'):
            logger.info(f"Logging out (LoginID: {g_login_id})...")
            res_logout = g_sdk.Logout(g_login_id)
            logger.info(f"Logout " + ("successful." if res_logout else "failed."))
            g_login_id = 0

        if g_sdk and hasattr(g_sdk, 'Cleanup'):
            logger.info("Cleaning up SDK resources..."); g_sdk.Cleanup()
            logger.info("SDK Cleanup complete.")
            g_sdk = None
        
        logging.shutdown()

if __name__ == "__main__":
    main()
