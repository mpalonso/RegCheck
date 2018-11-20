import winreg
"""
__author__ = "Mario Parra - mrb0b0t"
__license__ = "GPL"
__version__ = "0.2.0"
__maintainer__ = "mrb0b0t"
__status__ = "Testing"

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run (*)
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce (*)
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKLM\SYSTEM\CurrentControlSet\Control\hivelis
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
HKEY_LOCAL_MACHINE\Software\Classes\
"""
CurrentUserKeys = {r'Software\Microsoft\Windows\CurrentVersion\RunOnce', r'Software\Microsoft\Windows\CurrentVersion\Run',
r'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
r'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',}

LocalMachineKeys = {r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects',
r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs'}

DefaultValues = {'','','','','','','','',''}

def get_reg_value(reg):
	try:
		registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg, 0, winreg.KEY_READ)
		value, regtype = winreg.QueryValueEx(registry_key, reg)
		winreg.CloseKey(registry_key)
		return value
	except WindowsError:
		return None
def iter_element(element):
	for single in element:
		value = get_reg_value(single)
		print('[*]KEY: ' + str(single) + ' [*]Value: ' + str(value))

def main():
	regis = iter_element(CurrentUserKeys)
	print(regis)
if __name__ == '__main__':
	main()