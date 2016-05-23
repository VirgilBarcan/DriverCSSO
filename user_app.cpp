# include <windows.h>
# include <WINIOCTL.h>
# include <cstdio>

# define IOCTL_CREATE_FILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
# define IOCTL_DELETE_FILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
# define IOCTL_READ_FILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
# define IOCTL_WRITE_FILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

int main() {
	HANDLE hFile;
	DWORD dwReturn;
	char returnString[255] = { 0 };
	BOOL retVal;

	hFile = CreateFile(
		TEXT("\\\\.\\DriverCSSO"),
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	if (hFile) {
		retVal = DeviceIoControl(
			hFile,
			IOCTL_CREATE_FILE,
			"C:\\CSSO\\command2.txt",
			sizeof("C:\\CSSO\\command2.txt"),
			returnString,
			sizeof(returnString),
			&dwReturn,
			NULL);
		if (retVal) {
			printf("Received from the driver: %s %d\n", returnString, dwReturn);
		}

		CloseHandle(hFile);
	}

	return 0;
}