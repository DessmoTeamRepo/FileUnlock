![No Warranty](https://img.shields.io/badge/Warranty-None%20Given-red?style=for-the-badge&logo=exclamation-triangle)

![No Maintenance](https://img.shields.io/badge/Maintenance-None-red?style=for-the-badge&logo=tools)

![License](https://img.shields.io/badge/License-Educational%20MIT-orange?style=for-the-badge&logo=open-source-initiative)

# Go File Unlocker

This is a simple command-line tool for Windows that helps you find which process is locking a specific file. It can also list all locked files or list the files locked by a specific process.

## Building

To build the project, you need to have Go installed. Then, run the following command in the project directory:

```
go build
```

## Usage

```
file_unlocker.exe [options]
```

### Options

- `-list`: Lists all locked files and the processes that are locking them.
- `-pid <PID>`: Finds all files locked by a specific process ID.
- `-file <FILE>`: Finds the process that has a specific file locked.

## Important Note

This application requires the `BackgroundServices.dll` to be present in the same directory as the executable. If this DLL is missing, the application will not run and will show an error message. Please make sure to download the complete application package.

## Disclaimer

This tool is provided as-is and without any warranty. Use it at your own risk.
