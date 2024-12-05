#include <Windows.h>
#include <imagehlp.h>
#include <Commdlg.h>

#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <stdio.h>

#pragma comment (lib, "Dbghelp.lib")
#pragma comment (lib, "Imagehlp.lib")

using namespace std;

// Check if its 32bit or 64bit
WORD fileType = IMAGE_FILE_MACHINE_I386;

// Exported names
vector<string> names;

const vector<string> explode(const string &s, const char &c)
{
	string buff{""};
	vector<string> v;

	for (auto n : s)
	{
		if (n != c)
			buff += n;
		else if (n == c && buff != "")
		{
			v.push_back(buff);
			buff = "";
		}
	}
	if (buff != "")
		v.push_back(buff);

	return v;
}

bool getImageFileHeaders(string fileName, IMAGE_NT_HEADERS &headers)
{
	std::wstring wFileName = std::wstring(fileName.begin(), fileName.end());
	HANDLE fileHandle = CreateFile(
        wFileName.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0);
	if (fileHandle == INVALID_HANDLE_VALUE)
		return false;

	HANDLE imageHandle = CreateFileMapping(
		fileHandle,
		nullptr,
		PAGE_READONLY,
		0,
		0,
		nullptr);
	if (imageHandle == 0)
	{
		CloseHandle(fileHandle);
		return false;
	}

	void *imagePtr = MapViewOfFile(
		imageHandle,
		FILE_MAP_READ,
		0,
		0,
		0);
	if (imagePtr == nullptr)
	{
		CloseHandle(imageHandle);
		CloseHandle(fileHandle);
		return false;
	}

	PIMAGE_NT_HEADERS headersPtr = ImageNtHeader(imagePtr);
	if (headersPtr == nullptr)
	{
		UnmapViewOfFile(imagePtr);
		CloseHandle(imageHandle);
		CloseHandle(fileHandle);
		return false;
	}

	headers = *headersPtr;

	UnmapViewOfFile(imagePtr);
	CloseHandle(imageHandle);
	CloseHandle(fileHandle);

	return true;
}

void listDLLFunctions(string sADllName, vector<string> &slListOfDllFunctions)
{
	DWORD *dNameRVAs(0);
	DWORD *dNameRVAs2(0);
	IMAGE_EXPORT_DIRECTORY *ImageExportDirectory;
	unsigned long cDirSize;
	LOADED_IMAGE LoadedImage;
	string sName;
	slListOfDllFunctions.clear();
	if (MapAndLoad(sADllName.c_str(), NULL, &LoadedImage, TRUE, TRUE))
	{
		ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY *)ImageDirectoryEntryToData(LoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);

		if (ImageExportDirectory != NULL)
		{
			dNameRVAs = (DWORD *)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNames, NULL);

			for (size_t i = 0; i < ImageExportDirectory->NumberOfNames; i++)
			{
				sName = (char *)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, dNameRVAs[i], NULL);
				slListOfDllFunctions.push_back(sName);
			}
		}
		UnMapAndLoad(&LoadedImage);
	}
}

void generateDEF(string output, string name, vector<string> names)
{
	std::fstream file;
	file.open(output, std::ios::out);
	file << "LIBRARY " << name << endl;
	file << "EXPORTS" << endl;

	// Loop them
	for (int i = 0; i < names.size(); i++)
	{
		file << "\t" << names[i] << "=Fake" << names[i] << " @" << i + 1 << endl;
	}

	file.close();
}

void generateMainCPP(string output, string name, vector<string> names)
{
	size_t fileNameLength = name.size() + 6;
	std::fstream file;
	file.open(output, std::ios::out);
	file << "#define WIN32_LEAN_AND_MEAN" << endl
		<< "#include <windows.h>" << endl << endl
		<< "namespace Proxy" << endl
		<< "{" << endl
		<< "void Init(HMODULE hProxy);" << endl
		<< "}" << endl
		<< endl;

	file << "struct " << name << "_dll" << endl
		<< "{" << endl
		<< "    HMODULE dll;"
		<< endl;

	for (const auto &fn : names) {
		file << "    FARPROC Original" << fn << ";" << endl;
	}
	file << "} " << name << ";" << endl << endl;

	// Generate Functions
	if (fileType == IMAGE_FILE_MACHINE_AMD64) {
		// x86_64
		file << "extern \"C\"" << endl
			 << "{" << endl;

		for (const auto& fn : names) {
			file << "\tvoid Fake" << fn << "() { __asm { jmp[" << name << ".Original" << fn << "] } }" << endl;
		}

		file << "}" << endl;
	}
	else {
		// x86
		for (const auto& fn : names) {
			file << "__declspec(naked) void Fake" << fn << "() { __asm { jmp[" << name << ".Original" << fn << "] } }" << endl;
		}
	}

	file << endl;


	file << "namespace Proxy" << endl
		<< "{" << endl
		<< "void Init(HMODULE hProxy)" << endl
		<< "{";

    char buffer[1024]{ 0 };
    sprintf_s(buffer,
R"(
    wchar_t realDllPath[MAX_PATH];
    GetSystemDirectory(realDllPath, MAX_PATH);
    wcscat_s(realDllPath, L"\\%s.dll");
    auto OriginalModuleHandle = LoadLibrary(realDllPath);
    if (OriginalModuleHandle == nullptr) {
        MessageBox(nullptr, L"Cannot load original %s.dll library", L"Proxy", MB_ICONERROR);
        ExitProcess(0);
    }

#define RESOLVE(fn) %s.Original##fn = GetProcAddress(OriginalModuleHandle, #fn)
)",
name.c_str(), name.c_str(), name.c_str());

	file << buffer << endl;

    for (const auto& fn : names) {
        file << "    RESOLVE(" << fn << ");" << endl;
    }

	file << "} // Proxy::Init" << endl
		<< "} // namespace Proxy" << endl
		<< endl;

	file.close();
}

void generateASM(string name)
{
    std::fstream file;
    file.open(name + ".asm", std::ios::out);
    file << ".data" << endl;
    file << "extern PA : qword" << endl;
    file << ".code" << endl;
    file << "RunASM proc" << endl;
    file << "jmp qword ptr [PA]" << endl;
    file << "RunASM endp" << endl;
    file << "end" << endl;

    file.close();
}

void generateProxyHeader(string output, string name, vector<string> names)
{
    std::fstream file;
    file.open(output, std::ios::out);

    file << "#define WIN32_LEAN_AND_MEAN" << endl
        << "#include <windows.h>" << endl << endl
		<< "class Proxy" << endl
		<< "{" << endl
        << R"(public:
    static void Init(HMODULE hProxy);

    static inline HMODULE ProxyModuleHandle{};
    static inline HMODULE OriginalModuleHandle{};)" << endl
        << endl;

	size_t len = 4;
	for (const auto& fn : names) {
		len = len > fn.size() + 4 ? len : fn.size() + 4;
	}

    for (const auto& fn : names) {
		std::string pad(len - fn.size(), ' ');
        file << "    static inline decltype(" << fn << ")*" << pad << "Original" << fn << "{};" << endl;
    }

	file << "}; // Proxy" << endl;
	file.close();
}

void generateProxy(string output, string name, vector<string> names)
{
	std::fstream file;
	file.open(output, std::ios::out);

	file << "#include \"Proxy.h\"" << endl << endl
		<< "void Proxy::Init(HMODULE hProxy)" << endl
		<< "{";

	char buffer[1024]{ 0 };
	sprintf_s(buffer, 
R"(
	ProxyModuleHandle = hProxy;

    wchar_t realDllPath[MAX_PATH];
    GetSystemDirectory(realDllPath, MAX_PATH);
    wcscat_s(realDllPath, L"\\%s.dll");
    OriginalModuleHandle = LoadLibrary(realDllPath);
    if (OriginalModuleHandle == nullptr) {
        MessageBox(nullptr, L"Cannot load original %s.dll library", L"Proxy", MB_ICONERROR);
        ExitProcess(0);
    }

#define RESOLVE(fn) Original##fn = reinterpret_cast<decltype(Original##fn)>(GetProcAddress(OriginalModuleHandle, #fn)
)",
		name.c_str(), name.c_str());

	file << buffer << endl;

    size_t len = 1;
    for (const auto& fn : names) {
        len = len > fn.size() + 1 ? len : fn.size() + 1;
    }

	for (const auto& fn : names) {
		file << "    RESOLVE(" << fn << ");" << endl;
	}

	file << "#undef RESOLVE" << endl 
		<< "} // Proxy::Init" << endl
		<< endl;
	
	for (const auto& fn : names) {
		std::string pad(len - fn.size(), ' ');
		file << "__declspec(naked) void Fake"<< fn << "()" << pad << "{ __asm { jmp[Proxy::Original" << fn << "] } }" << endl;
	}

	file << endl;
	file.close();
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		cout << "[USAGE] DllProxyGenerator.exe <dll name>" << endl;
		return 1;
	}

	std::vector<std::string> args(argv, argv + argc);

    // Get filename
    vector<std::string> fileNameV = explode(args[1], '\\');
    std::string fileName = fileNameV[fileNameV.size() - 1];
    fileName = fileName.substr(0, fileName.size() - 4);

	IMAGE_NT_HEADERS headers;
	if (getImageFileHeaders(args[1], headers)) {
		fileType = headers.FileHeader.Machine;
	}
	
    cout << "\"" << fileName << ".dll\" is " << (fileType == IMAGE_FILE_MACHINE_AMD64 ? "64 bit" : "32 bit") << " executable file" << endl;

	cout << "listing exports of \"" << fileName << ".dll\"" << endl;

	// Get dll export names
	listDLLFunctions(args[1], names);

	cout << "found " << names.size() << " function" << (names.size() > 1 ? "s" : "") << endl;

	if (!CreateDirectoryA(fileName.c_str(), nullptr) && ERROR_ALREADY_EXISTS != GetLastError()) {
		cout << "unable to create output directory: " << fileName << endl;
		return 1;
	}

	cout << "exporting proxy to \".\\" << fileName << "\\\"" << endl;

	// Create Def File
	generateDEF(fileName + "\\exports.def", fileName, names);
	generateMainCPP(fileName + "\\dllproxy.cpp", fileName, names);

	generateProxyHeader(fileName + "\\Proxy.h", fileName, names);
	generateProxy(fileName + "\\Proxy.cpp", fileName, names);

	if (fileType == IMAGE_FILE_MACHINE_AMD64) {
		generateASM(fileName);
	}

	return 0;
}
