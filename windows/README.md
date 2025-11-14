Download these:

KAPE (zip)

Arsenal Image Mounter (MSI)

Autopsy 64-bit MSI

Copy them into: WADE = Ip of your server hosting the shares.

\\WADE\DataSources\windows_tools\KAPE\

KAPE ZIP from the vendor: e.g. KAPE2025.03.01.zip (any KAPE*.zip is fine).

\\WADE\DataSources\windows_tools\AIM\

Exactly what you have now: Arsenal-Image-Mounter-v3.12.331.zip.

\\WADE\DataSources\windows_tools\Autopsy\

Autopsy 64-bit Windows installer, ideally autopsy-<version>-64bit.msi.

On your Windows worker, run:

cd C:\WADE
powershell -ExecutionPolicy Bypass -File .\install_wade_windows.ps1
