@echo off
rem Runs on each clone after Windows setup finishes. Windows keeps its own
rem scrubbed copy of the answer file, so remove the one holding the password.
del /f /q C:\Windows\System32\Sysprep\clone-unattend.xml
