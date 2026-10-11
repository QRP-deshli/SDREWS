@echo off
setlocal enabledelayedexpansion
:: keygen.bat - generate all key material with OpenSSL (Windows).
:: Linux / macOS / Git Bash: use keygen.sh, it does exactly the same.
::
::   keygen.bat [output_dir]        default output_dir: keys
::
:: Existing files are NEVER overwritten, delete them by hand to rotate.
::   server_key.pem  server_crt.pem  master_key.h  ip_hash_key.h

cd /d "%~dp0"
set OUT=%~1
if "%OUT%"=="" set OUT=keys

where openssl >nul 2>nul
if errorlevel 1 (
    echo openssl not found in PATH. Install it ^(e.g. Git for Windows ships one in usr\bin^)
    echo or create the files by hand, see README.md.
    exit /b 1
)
if not exist "%OUT%" mkdir "%OUT%"

:: 1+2. P-256 private key and X.509 certificate (a pair, only created together)
if exist "%OUT%\server_key.pem" (
    echo kept existing %OUT%\server_key.pem and %OUT%\server_crt.pem
    goto key_done
)
openssl ecparam -name prime256v1 -genkey -noout -out "%OUT%\server_key.pem" || exit /b 1
openssl req -new -x509 -sha256 -key "%OUT%\server_key.pem" -out "%OUT%\server_crt.pem" -days 3650 -subj "/CN=pico2-https" || exit /b 1
echo created %OUT%\server_key.pem and %OUT%\server_crt.pem
:key_done

:: 3. 16-byte master key as master_key.h (kept if it already exists, clients depend on it)
if exist "%OUT%\master_key.h" goto master_done
for /f %%h in ('openssl rand -hex 16') do set MASTER_HEX=%%h
set MASTER_BYTES=
for /l %%i in (0,2,30) do set MASTER_BYTES=!MASTER_BYTES! 0x!MASTER_HEX:~%%i,2!,
> "%OUT%\master_key.h" echo const uint8_t MASTER_KEY[] = {!MASTER_BYTES! };
echo created %OUT%\master_key.h
:master_done

:: 4. 32-byte IP hash key as ip_hash_key.h (kept if it already exists)
if exist "%OUT%\ip_hash_key.h" goto iphash_done
for /f %%h in ('openssl rand -hex 32') do set IPHASH_HEX=%%h
set IPHASH_BYTES=
for /l %%i in (0,2,62) do set IPHASH_BYTES=!IPHASH_BYTES! 0x!IPHASH_HEX:~%%i,2!,
> "%OUT%\ip_hash_key.h" echo const uint8_t IP_HASH_KEY[] = {!IPHASH_BYTES! };
echo created %OUT%\ip_hash_key.h
:iphash_done

:: 5. Display the certificate only. The private key goes to OTP via key_provision, never to a header.
echo.
type "%OUT%\server_crt.pem"
echo.
echo Next: paste the certificate into server\web\certs.h, then follow README.md.
