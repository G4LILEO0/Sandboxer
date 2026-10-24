
  // Automatic download (ANA-4). The bytes are a harmless text file named like an executable.
  var blob = new Blob(['MZ-fixture-not-a-real-executable'], {type: 'application/octet-stream'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'invoice_2026.exe';
  document.body.appendChild(a); a.click();
