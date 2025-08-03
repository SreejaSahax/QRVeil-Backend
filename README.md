# QRVeil-Backend
ML Backend for QRVeil Browser extension.

The browser Extension detects QR codes on the active browser tab and scans it for their URL. The URL is then sent to the backend api server, where a trained xgboost model classifies it as safe or malicious. The URL along with its classifcation is displayed on the extension popup. 

<img width="504" height="480" alt="image (5)" src="https://github.com/user-attachments/assets/1ede97fa-6cb2-4d85-8cdc-ac62b195d96e" />
