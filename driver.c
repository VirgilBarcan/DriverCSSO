# include <ntddk.h>
# include <wdm.h>
# include <Ntstrsafe.h>
//# include <io_codes.h> 

# define IOCTL_CREATE_FILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
# define IOCTL_DELETE_FILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
# define IOCTL_READ_FILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
# define IOCTL_WRITE_FILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

NTSTATUS UnSupportedFunction(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	DbgPrint("[DRIVERCSSO][UnSupportedFunction]\n");

	return STATUS_SUCCESS;
}

NTSTATUS Close(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	DbgPrint("[DRIVERCSSO][Close]\n");

	return STATUS_SUCCESS;
}

NTSTATUS Create(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	DbgPrint("[DRIVERCSSO][Create]\n");

	return STATUS_SUCCESS;
}

NTSTATUS ExecuteCreateFile(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, unsigned int *pdwDataWritten) {
	NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
	char *pInputBuffer;
	char *pOutputBuffer;
	char *pReturnData = "IOCTL - Buffered IO From kernel";
	unsigned int dwDataRead = 0;

	HANDLE hFile;
	UNICODE_STRING usDosDevices;
	ANSI_STRING asFileName;
	UNICODE_STRING usFileName;
	UNICODE_STRING usFullFileName;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	char fileContent[100];
	int bufferSize = 100;

	DbgPrint("[DRIVERCSSO][ExecuteCreateFile]\n");

	pInputBuffer = Irp->AssociatedIrp.SystemBuffer;
	pOutputBuffer = Irp->AssociatedIrp.SystemBuffer;

	if (NULL != pInputBuffer && NULL != pOutputBuffer) {
		DbgPrint("[DRIVERCSSO][ExecuteCreateFile] FilePathBuffer = %s\n", pInputBuffer);

		RtlInitUnicodeString(&usDosDevices, L"\\DosDevices\\");

		RtlInitAnsiString(&asFileName, pInputBuffer);
		RtlAnsiStringToUnicodeString(&usFileName, &asFileName, TRUE);
	
		DbgPrint("[DRIVERCSSO][ExecuteCreateFile] FilePath = %Z\n", asFileName);
		DbgPrint("[DRIVERCSSO][ExecuteCreateFile] FilePath = %wZ\n", usFileName);
		
		usFullFileName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usDosDevices.Length + usFileName.Length, 'TAG1');
		usFullFileName.MaximumLength = usDosDevices.Length + usFileName.Length;
		usFullFileName.Length = 0;
		if (NULL != usFullFileName.Buffer) {

			RtlCopyUnicodeString(&usFullFileName, &usDosDevices);
			if (0 != usFullFileName.Length) {

				NtStatus = RtlUnicodeStringCat(&usFullFileName, &usFileName);
				if (STATUS_SUCCESS == NtStatus) {

					DbgPrint("[DRIVERCSSO][ExecuteCreateFile] FullFilePath = %wZ\n", usFileName);
					InitializeObjectAttributes(
						&objectAttributes,
						&usFullFileName,
						OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
						NULL,
						NULL);	

					//get the handle to the file
					NtStatus = ZwCreateFile(
						&hFile,
						GENERIC_ALL,
						&objectAttributes,
						&ioStatusBlock,
						NULL,
						FILE_ATTRIBUTE_NORMAL,
						0,
						FILE_CREATE,
						FILE_SYNCHRONOUS_IO_NONALERT,
						NULL,
						0);
					if (STATUS_SUCCESS == NtStatus) {
						//TODO
						DbgPrint("[DRIVERCSSO][ExecuteCreateFile] File Created!\n");
						ZwClose(hFile);
					}
					else {
						DbgPrint("[DRIVERCSSO][ExecuteCreateFile] File Not Created: %d\n", NtStatus);
					}
				}
			}
		}
	}

	return NtStatus;
}

NTSTATUS ExecuteDeleteFile(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, unsigned int *pdwDataWritten) {
	NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
	char *pInputBuffer;
	char *pOutputBuffer;
	char *pReturnData = "IOCTL - Buffered IO From kernel";
	unsigned int dwDataRead = 0, dwDataWritten = 0;

	HANDLE hFile;
	UNICODE_STRING usFileName;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatusBlock;

	DbgPrint("[DRIVERCSSO][ExecuteDeleteFile]\n");

	pInputBuffer = Irp->AssociatedIrp.SystemBuffer;
	pOutputBuffer = Irp->AssociatedIrp.SystemBuffer;

	if (NULL != pInputBuffer && NULL != pOutputBuffer) {
		DbgPrint("[DRIVERCSSO][ExecuteDeleteFile] FilePath = %s\n", pInputBuffer);

		RtlInitUnicodeString(&usFileName, L"\\DosDevices\\C:\\CSSO\\command.txt");
		InitializeObjectAttributes(
			&objectAttributes,
			&usFileName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			NULL);

		//get the handle to the file
		NtStatus = ZwCreateFile(
			&hFile,
			GENERIC_READ,
			&objectAttributes,
			&ioStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			0,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
		if (STATUS_SUCCESS == NtStatus) {
			//TODO
			ZwClose(hFile);
		}
	}

	return NtStatus;
}

NTSTATUS ExecuteReadFile(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, unsigned int *pdwDataWritten) {
	NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
	char *pInputBuffer;
	char *pOutputBuffer;
	char *pReturnData = "IOCTL - Buffered IO From kernel";
	unsigned int dwDataRead = 0, dwDataWritten = 0;

	HANDLE hFile;
	UNICODE_STRING usFileName;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	char fileContent[100];
	int bufferSize = 100;

	DbgPrint("[DRIVERCSSO][ExecuteReadFile]\n");

	pInputBuffer = Irp->AssociatedIrp.SystemBuffer;
	pOutputBuffer = Irp->AssociatedIrp.SystemBuffer;

	if (NULL != pInputBuffer && NULL != pOutputBuffer) {
		DbgPrint("[DRIVERCSSO][ExecuteReadFile] FilePath = %s\n", pInputBuffer);

		RtlInitUnicodeString(&usFileName, L"\\DosDevices\\C:\\CSSO\\command.txt");
		InitializeObjectAttributes(
			&objectAttributes,
			&usFileName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			NULL);

		//get the handle to the file
		NtStatus = ZwCreateFile(
			&hFile,
			GENERIC_READ,
			&objectAttributes,
			&ioStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			0,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
		if (STATUS_SUCCESS == NtStatus) {
			//read the content of the file
			NtStatus = ZwReadFile(
				hFile,
				NULL,
				NULL,
				NULL,
				&ioStatusBlock,
				fileContent,
				bufferSize,
				NULL,
				NULL);

			if (STATUS_SUCCESS == NtStatus) {
				fileContent[bufferSize - 1] = '\0';
				DbgPrint("[DRIVERCSSO][ExecuteReadFile] FileContent = \n%s\n", fileContent);
			}

			ZwClose(hFile);
		}
	}

	return NtStatus;
}

NTSTATUS ExecuteWriteFile(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, unsigned int *pdwDataWritten) {
	NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
	char *pInputBuffer;
	char *pOutputBuffer;
	char *pReturnData = "IOCTL - Buffered IO From kernel";
	unsigned int dwDataRead = 0, dwDataWritten = 0;

	HANDLE hFile;
	UNICODE_STRING usFileName;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	char fileContent[100];
	int bufferSize = 100;

	DbgPrint("[DRIVERCSSO][ExecuteWriteFile]\n");

	pInputBuffer = Irp->AssociatedIrp.SystemBuffer;
	pOutputBuffer = Irp->AssociatedIrp.SystemBuffer;

	if (NULL != pInputBuffer && NULL != pOutputBuffer) {
		DbgPrint("[DRIVERCSSO][ExecuteWriteFile] FilePath = %s\n", pInputBuffer);

		RtlInitUnicodeString(&usFileName, L"\\DosDevices\\C:\\CSSO\\command.txt");
		InitializeObjectAttributes(
			&objectAttributes,
			&usFileName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			NULL);

		//get the handle to the file
		NtStatus = ZwCreateFile(
			&hFile,
			GENERIC_READ,
			&objectAttributes,
			&ioStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			0,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
		if (STATUS_SUCCESS == NtStatus) {
			//TODO

			ZwClose(hFile);
		}
	}

	return NtStatus;
}

NTSTATUS IoControl(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	NTSTATUS NtStatus = STATUS_NOT_SUPPORTED;
	PIO_STACK_LOCATION pIoStackIrp = NULL;
	unsigned int dwDataWritten = 0;
	
	DbgPrint("[DRIVERCSSO][IoControl]\n");

	pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);

	if (NULL != pIoStackIrp) {
		switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode) {
			case IOCTL_CREATE_FILE:
				DbgPrint("[DRIVERCSSO][IoControl] IOCTL_CREATE_FILE\n");
				NtStatus = ExecuteCreateFile(Irp, pIoStackIrp, &dwDataWritten);
				break;
			case IOCTL_DELETE_FILE:
				DbgPrint("[DRIVERCSSO][IoControl] IOCTL_DELETE_FILE\n");
				NtStatus = ExecuteDeleteFile(Irp, pIoStackIrp, &dwDataWritten);
				break;
			case IOCTL_READ_FILE:
				DbgPrint("[DRIVERCSSO][IoControl] IOCTL_READ_FILE\n");
				NtStatus = ExecuteReadFile(Irp, pIoStackIrp, &dwDataWritten);
				break;		
			case IOCTL_WRITE_FILE:
				DbgPrint("[DRIVERCSSO][IoControl] IOCTL_WRITE_FILE\n");
				NtStatus = ExecuteWriteFile(Irp, pIoStackIrp, &dwDataWritten);
				break;	
			default:
				DbgPrint("[DRIVERCSSO][IoControl] default\n");
		}
	}

	Irp->IoStatus.Status = NtStatus;
	Irp->IoStatus.Information = dwDataWritten;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return NtStatus;
}

NTSTATUS ReadBufferedIO(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	DbgPrint("[DRIVERCSSO][ReadBufferedIO]\n");

	return STATUS_SUCCESS;
}

NTSTATUS WriteBufferedIO(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	DbgPrint("[DRIVERCSSO][WriteBufferedIO]\n");

	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT pDriverObject) {
	UNICODE_STRING usDosDeviceName;
	
	DbgPrint("[DRIVERCSSO][Unload]\n");

	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\DriverCSSO");
	IoDeleteSymbolicLink(&usDosDeviceName);

	IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	NTSTATUS NtStatus = STATUS_SUCCESS;
	unsigned int uiIndex = 0;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING usDriverName, usDosDeviceName;

	DbgPrint("[DRIVERCSSO][DriverEntry]: Begin\n");

	RtlInitUnicodeString(&usDriverName, L"\\Device\\DriverCSSO");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\DriverCSSO");

	NtStatus = IoCreateDevice(
		pDriverObject, 
		0,
		&usDriverName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&pDeviceObject);

	if (STATUS_SUCCESS == NtStatus) {
		for (uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; ++uiIndex) {
			pDriverObject->MajorFunction[uiIndex] = UnSupportedFunction;
			pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
			pDriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
			pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
			pDriverObject->MajorFunction[IRP_MJ_READ] = ReadBufferedIO;
			pDriverObject->MajorFunction[IRP_MJ_WRITE] = WriteBufferedIO;
		}

		pDriverObject->DriverUnload = Unload;

		pDeviceObject->Flags |= DO_BUFFERED_IO;

		IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
	}

	return STATUS_SUCCESS;
}