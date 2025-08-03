chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "scan") {
      chrome.tabs.captureVisibleTab(null, { format: "png" }, (dataUrl) => {
        const img = new Image();
        img.src = dataUrl;
  
        img.onload = () => {
          const canvas = new OffscreenCanvas(img.width, img.height);
          const ctx = canvas.getContext("2d");
          ctx.drawImage(img, 0, 0, img.width, img.height);
          const imageData = ctx.getImageData(0, 0, img.width, img.height);
          importScripts("jsQR.js");
          const code = jsQR(imageData.data, img.width, img.height);
          sendResponse({ qr: code ? code.data : null });
        };
  
        img.onerror = () => sendResponse({ qr: null });
      });
      return true;
    }
  });
  