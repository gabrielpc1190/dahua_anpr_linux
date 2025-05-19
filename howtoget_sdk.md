## Dahua NetSDK for Python: Acquisition and Installation

To use this ANPR data retrieval script, you must first obtain and install the appropriate Dahua NetSDK for Python. This SDK provides the necessary libraries and Python wrappers to communicate with Dahua devices.

### 1. Downloading the SDK

The Dahua NetSDK is typically provided by Dahua Technology or through their authorized distributors. It is not usually available on public package repositories like PyPI for direct `pip install` without the source file.

You will need to download the SDK package specific to your environment (Linux 64-bit in this case). An example download link for a version of the SDK is:

https://depp.dahuasecurity.com/integration/guide/download/SDK
[https://materialfile.dahuasecurity.com/uploads/soft/20250508/General_NetSDK_Eng_Python_linux64_IS_V3.060.0000000.0.R.250409.zip](https://materialfile.dahuasecurity.com/uploads/soft/20250508/General_NetSDK_Eng_Python_linux64_IS_V3.060.0000000.0.R.250409.zip)

**Important Considerations for Downloading:**
* **Official Sources**: Always try to obtain the SDK from official Dahua channels or your direct supplier to ensure you have a legitimate and up-to-date version.
* **Version Compatibility**: Ensure the SDK version you download is compatible with your camera's firmware version and your development environment (Linux 64-bit, Python 3.7+). The linked SDK is `General_NetSDK_Eng_Python_linux64_IS_V3.060.0000000.0.R.250409`.
* **File Naming**: The downloaded file will be a ZIP archive. The name might vary based on the version and release date.

### 2. Extracting the SDK Package

Once downloaded, extract the contents of the ZIP file to a known location on your server.
```bash
unzip General_NetSDK_Eng_Python_linux64_IS_V3.060.0000000.0.R.250409.zip -d ./Dahua_NetSDK_Python
```
(Replace the filename with the actual name of your downloaded ZIP file).

After extraction, you will find several files and directories. The key component for Python installation is a .whl (wheel) file.

3. Installing the Python Wheel Package
The SDK for Python is distributed as a .whl file. Based on your information and typical SDK structures, the file you need for a Linux 64-bit system would be named something like:

NetSDK-2.0.0.1-py3-none-linux_x86_64.whl

Note: The version number (2.0.0.1) in this example filename might differ from the version in the ZIP file name (V3.060...). Always use the .whl file that is actually present in the extracted SDK package. Look for a file with the .whl extension, typically in a dist subfolder or the root of the extracted SDK.

Installation Steps:

Activate your Python virtual environment (if you are using one, which is highly recommended):
```bash
source /path/to/your/venv/bin/activate
```
Navigate to the directory where you extracted the SDK and locate the .whl file.
For example, if you extracted to Dahua_NetSDK_Python and the wheel file is directly inside:
```cd Dahua_NetSDK_Python```

Install the .whl file using pip:
```pip install NetSDK-2.0.0.1-py3-none-linux_x86_64.whl```
(Replace NetSDK-2.0.0.1-py3-none-linux_x86_64.whl with the exact name of the wheel file you found in your extracted SDK).

This installation process will place the Python wrapper modules (NetSDK.py, SDK_Enum.py, SDK_Struct.py, SDK_Callback.py) and the necessary native Dahua libraries (.so files) into your Python environment's site-packages directory, typically under a NetSDK subdirectory.

4. Verifying Installation (Optional)
You can quickly verify if the Python modules are accessible by trying to import a core component:
```python
python -c "from NetSDK.NetSDK import NetClient; print('NetSDK import successful')"
```
If this runs without an ImportError, the Python part of the SDK is likely installed correctly. Runtime issues with native libraries might still occur if system dependencies are missing (see main README.md troubleshooting).

5. System Dependencies
Remember that the native Dahua SDK libraries themselves may have dependencies on other system libraries. For Debian/Ubuntu, these often include:
```bash
sudo apt-get update
sudo apt-get install -y libasound2 libxv1 libgl1-mesa-glx
```
After these steps, the Dahua NetSDK should be ready for the Python script to use.

**Points to Note in this Documentation:**

* It uses the specific download link you provided as an example but emphasizes finding the *actual* `.whl` file within the extracted package.
* It highlights the potential discrepancy between the version in the ZIP filename and the version in the `.whl` filename, instructing the user to use the name of the `.whl` file they find.
* It reinforces the use of a virtual environment.
* It includes a basic import test for verification.
* It reiterates the need for system library dependencies.

This should provide a clear guide for someone setting up the SDK for your project.

