@echo off
rem 一键打包 AssetMapper 为单文件 exe
cd /d %~dp0
pyinstaller --noconfirm --onefile --windowed --name AssetMapper run.py
echo.
echo 打包完成: dist\AssetMapper.exe
pause
