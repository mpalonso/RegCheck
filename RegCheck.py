import winreg
"""
__author__ = "Mario Parra - mrb0b0t"
__license__ = "GPL"
__version__ = "0.1.0"
__maintainer__ = "mrb0b0t"
__status__ = "Testing"


"""
reg_to_comp = r'Software\Microsoft\Windows\CurrentVersion\RunOnce'

def get_reg_value(reg):
	try:
		registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_to_comp, 0, winreg.KEY_READ)
		value, regtype = winreg.QueryValueEx(registry_key, reg)
		winreg.CloseKey(registry_key)
		return value
	except WindowsError:
		return None

def main():
	regis = get_reg_value(reg_to_comp)
	if regis == None:
		print('Clean')
	else:
		print(regis)
if __name__ == '__main__':
	main()