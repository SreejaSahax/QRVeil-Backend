const resultText = document.getElementById("result");
const copyBtn = document.getElementById("copy");
const openBtn = document.getElementById("open");

chrome.tabs.captureVisibleTab(null, { format: "png" }, (dataUrl) => {
  const img = new Image();
  img.src = dataUrl;

  img.onload = () => {
    if (img.width === 0 || img.height === 0) {
      resultText.textContent = "Screenshot too small to scan.";
      return;
    }

    const canvas = document.createElement("canvas");
    canvas.width = img.width;
    canvas.height = img.height;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(img, 0, 0);

    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, canvas.width, canvas.height);

    const url = code ? code.data : null;
    if (!url) {
      resultText.textContent = "No QR code detected.";
      return;
    }

    resultText.textContent = `Detected: ${url}\nChecking with backend...`;

    fetch('https://qrveil-backend.onrender.com/analyze_url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    })
    .then(res => res.json())
    .then(data => {
      resultText.textContent = `URL: ${data.url}\nResult: ${data.result}`;
    })
    .catch(err => {
      resultText.textContent = `URL: ${url}\nError contacting backend.`;
      console.error(err);
    });

    copyBtn.onclick = () => navigator.clipboard.writeText(url);
    openBtn.onclick = () => {
      if (url.startsWith("http")) window.open(url, "_blank");
      else alert("Not a valid link.");
    };
  };

  img.onerror = () => {
    resultText.textContent = "Screenshot load failed.";
  };
});
