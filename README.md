# Api para interceptar la consola de CS 1.6

```python
import pymem
import pymem.process
import struct
import ctypes

def attach_to_hl():
    try:
        pm = pymem.Pymem("hl.exe")
        return pm
    except pymem.exception.ProcessNotFound:
        return("No se encontró hl.exe ejecutándose.")
       

def get_engine_base(pm):
    engine_module = pymem.process.module_from_name(pm.process_handle, "engine.dll")
    return engine_module.lpBaseOfDll

def get_function_address(pm, engine_base):
    ecx_address = engine_base + 0x166BC4
    ecx_value = pm.read_int(ecx_address) + 0x15C
    func_address = pm.read_int(ecx_value + 0x50)
    return ecx_value, func_address

def execute_remote_command(pm, ecx_value, func_address, command):
    buffer_size = 64
    text_buffer = pm.allocate(buffer_size)
    encoded_command = command.encode("utf-8")
    data = encoded_command + b"\0"
    data_length = len(data)
    if data_length > buffer_size:
        text_buffer = pm.allocate(data_length)
    
    pm.write_bytes(text_buffer, data, data_length)
    
    shellcode = (
        b"\x60" + 
        b"\xB9" + struct.pack("<I", ecx_value) +
        b"\x68" + struct.pack("<I", text_buffer) +
        b"\xB8" + struct.pack("<I", func_address) +
        b"\xFF\xD0" +
        b"\x83\xC4\x04" +
        b"\x61" +
        b"\xC3"
    )
    
    shellcode_addr = pm.allocate(len(shellcode))
    pm.write_bytes(shellcode_addr, shellcode, len(shellcode))
    
    kernel32 = ctypes.windll.kernel32
    thread_handle = kernel32.CreateRemoteThread(pm.process_handle, None, 0, shellcode_addr, None, 0, None)
    if thread_handle:
        kernel32.WaitForSingleObject(thread_handle, 0xFFFFFFFF)
        return("Comando enviado correctamente con buffer.")
    else:
        return ("Error al crear el hilo remoto.")


def sendCommand(command):
    pm = attach_to_hl()
    if not pm:
        return
    
    engine_base = get_engine_base(pm)
    ecx_value, func_address = get_function_address(pm, engine_base)
    
    if func_address:
        execute_remote_command(pm, ecx_value, func_address, command)
    else:
        return("Error: No se pudo leer la dirección de la función.")

def changeName(name):
    sendCommand(f'name "{name}"')
    return "Name changed"

def say(text):
    sendCommand(f'say "{text}"')
    return "Name changed"

def teamSay(text):
    sendCommand(f'say_team "{text}"')
    return "Name changed"

def voiceRecord():
    sendCommand("+voicerecord")
    
def stopVoiceRecord():
    sendCommand("-voicerecord")

def toggleConsole():
    sendCommand("toggleconsole")

def connectToServer(ip):
    if not ":" in ip:
        print("ERROR: Missing port")
        return "Missing port"
    sendCommand(f"connect {ip}")

def disconnectServer():
    sendCommand("disconnect")

def disconnectServer():
    sendCommand("disconnect")

def showHud(state):
    if state == True:
     sendCommand("hud_draw 1")
     return "Hud enabled"
    if state == False:
     sendCommand("hud_draw 0")
     return "Hud Disabled"
    else:
        return "Invalid state"
    
def autoBuy():
    sendCommand("autobuy")

def kill():
    sendCommand("kill")

def recordDemo(name: str, path: str = None):
    if path:
        full_path = f"{path.rstrip('/')}/{name}"
    else:
        full_path = name 

    sendCommand(f"record {full_path}")

def reconnectToServer():
    sendCommand("retry")
```
