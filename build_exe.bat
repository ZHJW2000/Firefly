@echo off
rem 一键打包 AssetRadar 为单文件 exe
cd /d %~dp0
pyinstaller --noconfirm --onefile --windowed --name AssetRadar run.py
echo.
echo 打包完成: dist\AssetRadar.exe
pause
