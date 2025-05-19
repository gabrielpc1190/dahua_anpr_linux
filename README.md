# Dahua ANPR Camera Data Retrieval Script

This Python script connects to a Dahua ANPR (Automatic Number Plate Recognition) camera, subscribes to intelligent traffic events, and logs the received ANPR data, including license plate numbers, timestamps, and associated vehicle information.

## How It Works

The script utilizes the Dahua NetSDK for Python to interact with the camera. The process involves:
1.  **SDK Initialization**: Loading and initializing the Dahua NetSDK libraries.
2.  **Device Login**: Authenticating and establishing a session with the ANPR camera using its IP address and credentials.
3.  **Event Subscription**: Subscribing to a stream of intelligent events from the camera. The script is configured to listen for `EM_EVENT_IVS_TYPE.ALL` to capture various events, with specific parsing logic for ANPR-related event types like `TRAFFICJUNCTION`, `TRAFFICGATE`, and `TRAFFIC_MANUALSNAP`.
4.  **Callback Handling**: A callback function (`AnalyzerDataCallback`) is registered with the SDK. This function is invoked by the SDK whenever a subscribed event is received from the camera.
5.  **Data Parsing**: Inside the callback, the received event data (which is a C-style structure) is cast to the appropriate Python structure based on the event type. Relevant information such as license plate number, timestamp, vehicle color, plate color, and vehicle type is then extracted.
    * The script includes a helper function (`extract_anpr_details`) to centralize the logic for pulling common ANPR details from different event structures.
    * **Note**: The accuracy of data extraction depends on the specific field names in the `SDK_Struct.py` file provided with your Dahua Python SDK version. You may need to adjust these in the script.
6.  **Logging**: All significant operations, received event data, and errors are logged to both the console and a file (`anpr_events.log` by default).
7.  **Graceful Shutdown**: The script handles `Ctrl+C` to stop event subscription, log out from the camera, and clean up SDK resources.

## Dependencies

### Python
* Python 3.7+ (as recommended by the Dahua NetSDK Python Programming Manual V2.0.0)

### Dahua NetSDK
* **Dahua NetSDK Python Package**: This is the primary dependency. It's typically provided as a `.whl` file (e.g., `NetSDK-2.0.0.1-py3-none-linux_x86_64.whl`). You need to obtain this from Dahua or your camera/SDK provider.
    * The SDK package includes Python wrapper modules (`NetSDK.py`, `SDK_Enum.py`, `SDK_Struct.py`, `SDK_Callback.py`) and the necessary underlying native shared libraries (`.so` files for Linux, `.dll` for Windows).

### System Libraries (Linux - Debian/Ubuntu example)
The native Dahua SDK libraries have dependencies on certain system libraries. Based on our troubleshooting, the following are required:
* `libasound2`: For ALSA sound support (even if not directly used for audio output by this script, SDK components might link against it).
* `libxv1`: X Window System video extension library.
* `libgl1` or `libgl1-mesa-glx`: Core OpenGL library.

These are often required by the rendering or playback components of the SDK, which might be initialized even if this script only focuses on event data.

## Setup

1.  **Clone the Repository (if applicable)**
    ```bash
    git clone [your-repo-url]
    cd [your-repo-name]
    ```

2.  **Create and Activate a Python Virtual Environment (Recommended)**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dahua NetSDK Python Package**
    * Place the Dahua NetSDK `.whl` file (e.g., `NetSDK-2.0.0.1-py3-none-linux_x86_64.whl`) in the project directory or a known location.
    * Install it using pip:
        ```bash
        pip install /path/to/your/NetSDK-*.whl
        ```

4.  **Install System Dependencies (Debian/Ubuntu Example)**
    ```bash
    sudo apt-get update
    sudo apt-get install -y libasound2 libxv1 libgl1-mesa-glx
    ```
    (Package names might vary slightly on other Linux distributions).

5.  **Configure Script Settings**
    * Open `get_plates.py` in a text editor.
    * Update the following configuration variables with your camera's details:
        ```python
        CAMERA_IP = "YOUR_CAMERA_IP_ADDRESS"
        CAMERA_PORT = 37777 # Or your camera's specific TCP port
        USERNAME = "YOUR_CAMERA_USERNAME"
        PASSWORD = "YOUR_CAMERA_PASSWORD"
        LOG_FILE = "anpr_events.log" # Desired log file name
        # ANPR_EVENT_TYPE is set to EM_EVENT_IVS_TYPE.ALL by default
        ```

6.  **Configure Camera for ANPR Event Upload**
    * Access your Dahua ANPR camera's web interface.
    * Ensure that ANPR/Intelligent Analysis features are enabled.
    * Define detection rules and areas (e.g., tripwire, intrusion zone for vehicle detection).
    * Make sure the camera is configured to trigger and upload events (like `TRAFFICJUNCTION` or other relevant traffic events) when a license plate is detected. Refer to your camera's operation manual (e.g., "Smart ANPR Camera Web 5.0 Operation Manual") for specific instructions.

## Usage

It's recommended to use the provided wrapper script `run_anpr.sh` as it sets the necessary `LD_LIBRARY_PATH` for the Dahua SDK's native libraries.

1.  **Make the wrapper script executable:**
    ```bash
    chmod +x run_anpr.sh
    ```

2.  **Run the script using the wrapper:**
    ```bash
    ./run_anpr.sh
    ```
    The script will:
    * Attempt to initialize the SDK and log in to the camera.
    * Subscribe to ANPR events.
    * Log output to the console and to the specified `LOG_FILE` (e.g., `anpr_events.log`).
    * Wait for events. When an ANPR event is received, details like plate number, timestamp, etc., will be logged.

3.  **To stop the script, press `Ctrl+C` in the terminal where it's running.** The script will attempt to log out and clean up SDK resources.

## Troubleshooting

* **"CRITICAL: Failed to import Dahua NetSDK modules..."**:
    * Ensure the Dahua NetSDK `.whl` package was installed correctly into your active Python virtual environment.
* **Initial "动态库加载失败" (Dynamic library loading failed) message in script output (now resolved, but for reference):**
    * This indicated missing system dependencies for the Dahua SDK's native libraries. Installing `libasound2`, `libxv1`, and `libgl1` (or `libgl1-mesa-glx`) and ensuring execute permissions on the `.so` files usually resolves this. The `run_anpr.sh` script handles `LD_LIBRARY_PATH`.
* **"主连接失败" (Main connection failed) during login:**
    * Verify `CAMERA_IP`, `CAMERA_PORT`, `USERNAME`, `PASSWORD` in `get_plates.py`.
    * Check network connectivity to the camera (ping, telnet to the port).
    * Ensure no firewalls are blocking the connection.
    * Check the camera's web interface for any IP filters or access restrictions.
* **Events Received, but "N/A" or Incorrect Data (Plate Number, Colors, etc.)**:
    * This means the field names or structure access in the `extract_anpr_details` function of `get_plates.py` do not match your specific SDK version's `SDK_Struct.py` file.
    * You need to open `/path/to/your/venv/lib/python3.11/site-packages/NetSDK/SDK_Struct.py` (adjust Python version if needed).
    * Find the Python class definition for the event structure being reported (e.g., `DEV_EVENT_TRAFFICJUNCTION_INFO`).
    * Inspect its `_fields_` to get the correct member names for plate number, time, colors, etc.
    * Update the `extract_anpr_details` function in `get_plates.py` with the correct field access paths.
* **No Events Received**:
    * Ensure ANPR is properly configured and enabled on the camera itself (detection rules, zones, event linkage).
    * Test if the camera is generating ANPR events by checking its own live view or event logs via the web interface.
    * Make sure vehicles are passing through the correctly configured detection zone.

## Log File
The script logs its operations and received ANPR data to `anpr_events.log` (or the filename specified in `LOG_FILE`). This file is useful for debugging and reviewing captured plate information.

## Important Notes
* The Dahua SDK and its Python wrappers are proprietary. You must obtain them legally from Dahua or an authorized distributor.
* The exact names of SDK structures and enumeration members can vary slightly between SDK versions. Always refer to the `SDK_Struct.py` and `SDK_Enum.py` files included with your specific SDK installation for the most accurate information.
* This script assumes the Dahua SDK native libraries are located in a `Libs/linux64` subdirectory within the `NetSDK` site-package, which seems to be a common structure for their Python SDKs. The `run_anpr.sh` script sets `LD_LIBRARY_PATH` accordingly.
