#!/usr/bin/env python3

import time
import sys
import logging
import csv
import os
from ctypes import c_void_p, cast, POINTER, c_char_p, sizeof, string_at

# --- SDK Import Block ---
try:
    from NetSDK.NetSDK import NetClient
    from NetSDK.SDK_Enum import EM_LOGIN_SPAC_CAP_TYPE, EM_EVENT_IVS_TYPE, EM_VEHICLE_DIRECTION # Add EM_VEHICLE_DIRECTION
    from NetSDK.SDK_Struct import NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY
    from NetSDK.SDK_Struct import DEV_EVENT_TRAFFICJUNCTION_INFO, NET_A_DEV_EVENT_TRAFFICGATE_INFO, \
                                  NET_A_DEV_EVENT_TRAFFICSNAPSHOT_INFO, NET_DEV_EVENT_TRAFFIC_MANUALSNAP_INFO
    from NetSDK.SDK_Struct import SDK_MSG_OBJECT, NET_A_MSG_OBJECT, DEV_EVENT_TRAFFIC_TRAFFICCAR_INFO, NET_TIME_EX, \
                                  SDK_RECT, NET_RECT_EX # Ensure RECT types are imported
    from NetSDK.SDK_Callback import fDisConnect, fHaveReConnect, fAnalyzerDataCallBack
except ImportError as e:
    print(f"CRITICAL: Failed to import Dahua NetSDK modules: {e}")
    sys.exit(1)
except Exception as e:
    print(f"CRITICAL: Unexpected error during SDK import: {e}")
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
CSV_FILE = "anpr_records_sdk.csv" # New CSV filename
CSV_HEADERS = [
    "Blocklist", "VehicleType", "PlateColor", "PlateNo", "PlateSize", "Allowlist",
    "SnapshotSource", "SubscribedPlatformIP", "Time", "VehicleColor",
    "VehicleFrontOrBack", "VehicleLogo", "SDKEventType", "ImageSize"
]

# --- Global Variables & Logging Setup (same as before) ---
g_sdk, g_login_id, g_analyzer_handle = None, 0, 0
log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(module)s.%(funcName)s: %(message)s')
file_handler, console_handler = logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)
file_handler.setFormatter(log_formatter); file_handler.setLevel(logging.INFO)
console_handler.setFormatter(log_formatter); console_handler.setLevel(logging.INFO)
logger = logging.getLogger(); logger.setLevel(logging.INFO)
if not logger.handlers:
    logger.addHandler(file_handler); logger.addHandler(console_handler)

# --- Enum Mappings (VERIFY THESE WITH YOUR SDK_Enum.py!) ---
# These are examples and need to be accurate based on your SDK files
VEHICLE_TYPE_MAP = { 0: "Unknown", 1: "Motor", 2: "Non-Motor", 3: "Bus", 4: "Bicycle", 5: "Motorcycle",
                     6: "PassengerCar", 7: "LargeTruck", 8: "MidTruck", 9: "SaloonCar", 10: "Microbus",
                     11: "MicroTruck", 12: "Tricycle", 13: "Passerby", 14: "DregsCar",
                     15: "Tanker", 16: "SUV/MPV", 17: "Pickup", 18: "Light Truck"} # Adjust from your TrafficSnapEventInfo.CSV

# EM_VEHICLE_DIRECTION (from NetSDK.SDK_Enum if available, or map based on observation)
VEHICLE_DIRECTION_MAP = {
    0: "Unknown", # Or based on SDK_Enum
    1: "Vehicle Front", # Example: EM_VEHICLE_DIRECTION.HEAD
    2: "Vehicle Back",  # Example: EM_VEHICLE_DIRECTION.REAR
    3: "Side"           # Example
}

# --- CSV Handling (initialize_csv, append_to_csv - same as before) ---
def initialize_csv():
    file_exists = os.path.isfile(CSV_FILE)
    is_empty = False
    if file_exists: is_empty = os.path.getsize(CSV_FILE) == 0
    if not file_exists or is_empty:
        try:
            with open(CSV_FILE, mode='w', newline='', encoding='utf-8') as csvfile:
                csv.writer(csvfile).writerow(CSV_HEADERS)
            logger.info(f"CSV file '{CSV_FILE}' initialized with headers.")
        except IOError as e: logger.error(f"Error initializing CSV: {e}")

def append_to_csv(data_row):
    try:
        with open(CSV_FILE, mode='a', newline='', encoding='utf-8') as csvfile:
            csv.writer(csvfile).writerow(data_row)
    except IOError as e: logger.error(f"Error writing to CSV: {e}")

# --- Callback Functions (DisconnectCallback, ReconnectCallback - same as before) ---
@fDisConnect
def DisconnectCallback(lLoginID, pchDVRIP, nDVRPort, dwUser):
    ip = pchDVRIP.decode('utf-8', errors='ignore') if pchDVRIP else "Unknown"
    logger.warning(f"DISCONNECTED - ID:{lLoginID}, IP:{ip}:{nDVRPort}\n")

@fHaveReConnect
def ReconnectCallback(lLoginID, pchDVRIP, nDVRPort, dwUser):
    ip = pchDVRIP.decode('utf-8', errors='ignore') if pchDVRIP else "Unknown"
    logger.info(f"RECONNECTED - ID:{lLoginID}, IP:{ip}:{nDVRPort}\n")


@fAnalyzerDataCallBack
def AnalyzerDataCallback(lAnalyzerHandle, dwAlarmType, pAlarmInfo, pBuffer, dwBufSize, dwUser, nSequence, reserved):
    logger.info(f"Event Received - Handle:{lAnalyzerHandle}, AlarmType:{dwAlarmType}({hex(dwAlarmType)}), Seq:{nSequence}")

    event_type_str = f"SDKEventType({dwAlarmType})"
    csv_data = {header: "N/A" for header in CSV_HEADERS} # Initialize with defaults
    csv_data["SDKEventType"] = event_type_str
    csv_data["SubscribedPlatformIP"] = "" # Cannot get this from SDK event
    csv_data["ImageSize"] = dwBufSize if pBuffer and dwBufSize > 0 else 0
    
    event_struct_map = {
        EM_EVENT_IVS_TYPE.TRAFFICJUNCTION: ("TRAFFICJUNCTION", DEV_EVENT_TRAFFICJUNCTION_INFO),
        EM_EVENT_IVS_TYPE.TRAFFICGATE: ("TRAFFICGATE", NET_A_DEV_EVENT_TRAFFICGATE_INFO),
        EM_EVENT_IVS_TYPE.TRAFFIC_MANUALSNAP: ("TRAFFIC_MANUALSNAP", NET_DEV_EVENT_TRAFFIC_MANUALSNAP_INFO),
        # TRAFFICSNAPSHOT is complex, handle separately if needed
    }

    if dwAlarmType in event_struct_map:
        event_name_for_log, StructType = event_struct_map[dwAlarmType]
        csv_data["EventType"] = event_name_for_log # Use the SDK event name for this field

        try:
            event_info = cast(pAlarmInfo, POINTER(StructType)).contents

            # Time
            if hasattr(event_info, 'UTC') and isinstance(event_info.UTC, NET_TIME_EX):
                utc = event_info.UTC
                csv_data["Time"] = f"{utc.dwYear:04d}-{utc.dwMonth:02d}-{utc.dwDay:02d} {utc.dwHour:02d}:{utc.dwMinute:02d}:{utc.dwSecond:02d}"
                # Milliseconds are optional based on target CSV format
                # if hasattr(utc, 'dwMillisecond'): csv_data["Time"] += f".{utc.dwMillisecond:03d}"

            # Primary ANPR data often in stTrafficCar
            if hasattr(event_info, 'stTrafficCar') and isinstance(event_info.stTrafficCar, DEV_EVENT_TRAFFIC_TRAFFICCAR_INFO):
                traffic_car = event_info.stTrafficCar
                if hasattr(traffic_car, 'szPlateNumber'):
                    csv_data["PlateNo"] = traffic_car.szPlateNumber.decode('utf-8', errors='ignore').strip('\x00').strip()
                if hasattr(traffic_car, 'szPlateColor'):
                    csv_data["PlateColor"] = traffic_car.szPlateColor.decode('utf-8', errors='ignore').strip('\x00').strip()
                if hasattr(traffic_car, 'szVehicleColor'):
                    csv_data["VehicleColor"] = traffic_car.szVehicleColor.decode('utf-8', errors='ignore').strip('\x00').strip()
                if hasattr(traffic_car, 'emCarType'): # Enum
                    csv_data["VehicleType"] = VEHICLE_TYPE_MAP.get(traffic_car.emCarType, f"EnumVal:{traffic_car.emCarType}")
                if hasattr(traffic_car, 'szVehicleSign'):
                    csv_data["VehicleLogo"] = traffic_car.szVehicleSign.decode('utf-8', errors='ignore').strip('\x00').strip()
                if hasattr(traffic_car, 'stuBlackList') and hasattr(traffic_car.stuBlackList, 'bIsBlackCar'):
                    csv_data["Blocklist"] = "Yes" if traffic_car.stuBlackList.bIsBlackCar else "No"
                if hasattr(traffic_car, 'stuWhiteList') and hasattr(traffic_car.stuWhiteList, 'bTrustCar'):
                    csv_data["Allowlist"] = "Yes" if traffic_car.stuWhiteList.bTrustCar else "No"
            
            # Fallback for Plate Number if not in stTrafficCar
            if csv_data["PlateNo"] == "N/A" and hasattr(event_info, 'stuObject'):
                 if hasattr(event_info.stuObject, 'szText'):
                    plate_cand = event_info.stuObject.szText.decode('utf-8', errors='ignore').strip('\x00').strip()
                    if plate_cand: csv_data["PlateNo"] = plate_cand

            # Plate Size (from stuObject.BoundingBox)
            obj_for_bbox = None
            if hasattr(event_info, 'stuObject'): # SDK_MSG_OBJECT or NET_A_MSG_OBJECT
                obj_for_bbox = event_info.stuObject
            
            if obj_for_bbox and hasattr(obj_for_bbox, 'BoundingBox'):
                bbox = obj_for_bbox.BoundingBox
                if all(hasattr(bbox, attr) for attr in ['left', 'top', 'right', 'bottom']):
                    width = bbox.right - bbox.left
                    height = bbox.bottom - bbox.top
                    if width >= 0 and height >= 0: # Basic sanity check
                         csv_data["PlateSize"] = f"{width}*{height}"

            # VehicleFrontOrBack
            if hasattr(event_info, 'byVehicleDirection'): # Directly on event for TRAFFICJUNCTION
                csv_data["VehicleFrontOrBack"] = VEHICLE_DIRECTION_MAP.get(event_info.byVehicleDirection, f"EnumVal:{event_info.byVehicleDirection}")
            elif hasattr(event_info, 'stTrafficCar') and hasattr(event_info.stTrafficCar, 'byDirection'): # From stTrafficCar
                 # Note: stTrafficCar.byDirection has a different meaning (lane direction)
                 # We need a specific field for vehicle front/back.
                 # If DEV_EVENT_TRAFFIC_TRAFFICCAR_INFO has a 'byVehicleDirection' or similar, use that.
                 # For now, we'll assume the top-level one if available.
                 pass


            # Snapshot Source (Heuristic)
            # dwSnapFlagMask: 0位:"*",1位:"Timing",2位:"Manual",3位:"Marked",4位:"Event"
            if hasattr(event_info, 'dwSnapFlagMask'):
                if event_info.dwSnapFlagMask & (1 << 4): # Event triggered
                    csv_data["SnapshotSource"] = "EventTrigger" # Or "Video" if that's how camera maps it
                elif event_info.dwSnapFlagMask & (1 << 2): # Manual
                    csv_data["SnapshotSource"] = "Manual"
                elif event_info.dwSnapFlagMask & (1 << 1): # Timing
                    csv_data["SnapshotSource"] = "Timing"
                else:
                    csv_data["SnapshotSource"] = "UnknownSDKFlag"
            elif hasattr(event_info, 'stCommInfo') and hasattr(event_info.stCommInfo, 'emSnapCategory'):
                # This is EM_SNAPCATEGORY, needs mapping
                csv_data["SnapshotSource"] = f"SnapCatEnum:{event_info.stCommInfo.emSnapCategory}"


            # Log extracted data before writing to CSV for easier debugging
            logger.info(f"  Extracted for CSV ({event_name_for_log}): Plate='{csv_data['PlateNo']}', Time='{csv_data['Time']}', PlateColor='{csv_data['PlateColor']}', VehicleColor='{csv_data['VehicleColor']}', VehicleType='{csv_data['VehicleType']}'")

            # Write to CSV
            if csv_data["PlateNo"] != "N/A" and csv_data["PlateNo"] != "":
                row_to_write = [csv_data.get(h, "N/A_Field") for h in CSV_HEADERS]
                append_to_csv(row_to_write)

        except Exception as e:
            logger.error(f"  Error processing {event_name_for_log} for CSV: {e}", exc_info=True)

    elif dwAlarmType == EM_EVENT_IVS_TYPE.TRAFFICSNAPSHOT:
        event_type_str = "TRAFFICSNAPSHOT (Aggregate)"
        logger.info(f"  Event Type: {event_type_str}. This event aggregates multiple captures. Detailed CSV export requires iterating sub-structures and is not fully implemented here.")
        # To implement this, you would cast to NET_A_DEV_EVENT_TRAFFICSNAPSHOT_INFO
        # then loop through event_info.stuCarWayInfo array. Each element of stuCarWayInfo
        # contains stuSigInfo which in turn has the ANPR details for one capture.
        # You would call append_to_csv for each individual capture within this event.

    else:
        logger.info(f"  Event Type {event_type_str} not listed for detailed ANPR CSV export.")

    logger.info(f"----------------------------------\n")

# --- Main Application Logic (largely unchanged from previous logging version) ---
def main():
    global g_sdk, g_login_id, g_analyzer_handle
    initialize_csv()
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
    login_req.szIP = CAMERA_IP.encode('utf-8'); login_req.nPort = CAMERA_PORT
    login_req.szUserName = USERNAME.encode('utf-8'); login_req.szPassword = PASSWORD.encode('utf-8')
    login_req.emSpecCap = EM_LOGIN_SPAC_CAP_TYPE.TCP; login_req.pCapParam = None
    login_res = NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY()
    login_res.dwSize = sizeof(NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY)
    login_result_tuple = g_sdk.LoginWithHighLevelSecurity(login_req, login_res)
    if isinstance(login_result_tuple, tuple) and len(login_result_tuple) == 3:
        g_login_id, error_msg_str = login_result_tuple[0], login_result_tuple[2]
    else:
        logger.error(f"Unexpected login result: {login_result_tuple}")
        g_login_id, error_msg_str = 0, "SDK Login format error."
    if g_login_id == 0:
        logger.error(f"Login Failed. SDK Msg: '{error_msg_str}'. Check credentials/network.")
        if hasattr(g_sdk, 'Cleanup'): g_sdk.Cleanup()
        return
    logger.info(f"Login successful. LoginID: {g_login_id}")
    logger.info(f"Subscribing to ALL IVS events (Type Code: {ANPR_EVENT_TYPE}, Channel: {CHANNEL_ID})...")
    g_analyzer_handle = g_sdk.RealLoadPictureEx(g_login_id, CHANNEL_ID, ANPR_EVENT_TYPE, 1, AnalyzerDataCallback, 0, None)
    if g_analyzer_handle == 0:
        logger.error(f"Failed to subscribe (RealLoadPictureEx returned 0).")
        if hasattr(g_sdk, 'Logout'): g_sdk.Logout(g_login_id)
        if hasattr(g_sdk, 'Cleanup'): g_sdk.Cleanup()
        return
    logger.info(f"Subscribed. AnalyzerHandle: {g_analyzer_handle}. Waiting for events... Ctrl+C to exit.")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt: logger.info("\nCtrl+C. Exiting...")
    except Exception as e: logger.error(f"\nMain loop error: {e}", exc_info=True)
    finally:
        if g_analyzer_handle and g_sdk and hasattr(g_sdk, 'StopLoadPic'):
            logger.info(f"Stopping subscription (Handle: {g_analyzer_handle})...")
            res_stop = g_sdk.StopLoadPic(g_analyzer_handle)
            logger.info(f"Subscription stopped " + ("OK." if res_stop else "FAIL."))
        if g_login_id and g_sdk and hasattr(g_sdk, 'Logout'):
            logger.info(f"Logging out (ID: {g_login_id})...")
            res_logout = g_sdk.Logout(g_login_id)
            logger.info(f"Logout " + ("OK." if res_logout else "FAIL."))
        if g_sdk and hasattr(g_sdk, 'Cleanup'):
            logger.info("Cleaning SDK..."); g_sdk.Cleanup()
            logger.info("SDK Cleanup OK.")
        logging.shutdown()

if __name__ == "__main__":
    main()
