#include <iostream>
#include <cstdlib>
#include <windows.h>
#include <string>
#include <intrin.h>
#include <array>
#include <memory>
#include <sstream>

#include "color.h"

void SBStat()
{
    const std::string SBstat = "powershell -command \"Confirm-SecureBootUEFI\"";
    std::array<char, 128> SB;
    std::string SBstatL;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(SBstat.c_str(), "r"), _pclose);

    while (fgets(SB.data(), SB.size(), pipe.get()) != nullptr) {
        SBstatL += SB.data();
    }

    if (SBstatL.find("True") != std::string::npos) {
        print::set_text("SecureBoot : Enabled\n", Green);
    }
    else {
        print::set_text("SecureBoot : Disabled\n", Red);
    }

}

void TPMStat() {
    const std::string TPMStat = "powershell -command \"(Get - Tpm).TpmReady\"";
    std::array<char, 128> TPM;
    std::string TPMStatL;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(TPMStat.c_str(), "r"), _pclose);

    while (fgets(TPM.data(), TPM.size(), pipe.get()) != nullptr) {
        TPMStatL += TPM.data();
    }

    if (TPMStatL.find("True") != std::string::npos) {
        print::set_text("TPM : Enabled\n", Green);
    }
    else if (TPMStatL.find("False") != std::string::npos) {
        print::set_text("TPM : Disabled\n", Red);
    }

}

void HVCIStat()
{
    HKEY hKey;
    DWORD HVCIStat;
    DWORD lhvci = sizeof(HVCIStat);

    LPCWSTR subKey = L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity";

    RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey);
    RegQueryValueExW(hKey, L"Enabled", nullptr, nullptr, reinterpret_cast<LPBYTE>(&HVCIStat), &lhvci);

    if (HVCIStat == 1) {
        print::set_text(("HVCI : Enabled \n"), Green);
    }
    else {
        print::set_text(("HVCI : Disabled \n"), Red);
    }

    RegCloseKey(hKey);

}

void VT() {
    const std::string VTstat = "powershell -command \"(Get-CimInstance -ClassName Win32_ComputerSystem).HypervisorPresent\"";
    std::array<char, 128> VT;
    std::string VTstatL;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(VTstat.c_str(), "r"), _pclose);

    while (fgets(VT.data(), VT.size(), pipe.get()) != nullptr) {
        VTstatL += VT.data();
    }

    if (VTstatL.find("True") != std::string::npos) {
        print::set_text("Virtualization : Enabled\n", Green);
    }
    else if (VTstatL.find("False") != std::string::npos) {
        print::set_text("Virtualization : Disabled\n", Red);
    }
}

void VBSStat()
{
    const std::string VBSStat = "powershell -command \"(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard).VirtualizationBasedSecurityStatus\"";
    std::array<char, 128> VBS;
    std::string VBSStatL;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(VBSStat.c_str(), "r"), _pclose);

    while (fgets(VBS.data(), VBS.size(), pipe.get()) != nullptr) {
        VBSStatL += VBS.data();
    }

    if (VBSStatL.find("0") != std::string::npos) {
        print::set_text("VBS : Disabled\n", Red);
    }
    else if (VBSStatL.find("1") != std::string::npos) {
        print::set_text("VBS : Enabled\n", Green);
    }
    else if (VBSStatL.find("2") != std::string::npos) {
        print::set_text("VBS : Enabled(partial)\n", LightMagenta);
    }
}

void RTPStat()
{
    const std::string RTPStat = "powershell -command \"(Get-MpPreference).DisableRealtimeMonitoring\"";
    std::array<char, 128> RTP;
    std::string RTPStatL;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(RTPStat.c_str(), "r"), _pclose);

    while (fgets(RTP.data(), RTP.size(), pipe.get()) != nullptr) {
        RTPStatL += RTP.data();
    }

    if (RTPStatL.find("False") != std::string::npos) {
        print::set_text("RealTime Protection : Enabled \n", Green);
    }
    else if (RTPStatL.find("True") != std::string::npos) {
        print::set_text("RealTime Protection : Disabled \n", Red);
    }
}

void FirewallStat()
{
    HKEY hKey;
    DWORD DomStat;
    DWORD PrvStat;
    DWORD PubStat;
    DWORD lDom = sizeof(DomStat);
    DWORD lPrv = sizeof(PrvStat);
    DWORD lPub = sizeof(PubStat);

    RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile", 0, KEY_READ, &hKey);
    RegQueryValueExW(hKey, L"EnableFirewall", nullptr, nullptr, reinterpret_cast<LPBYTE>(&DomStat), &lDom);
    RegCloseKey(hKey);

    RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile", 0, KEY_READ, &hKey);
    RegQueryValueExW(hKey, L"EnableFirewall", nullptr, nullptr, reinterpret_cast<LPBYTE>(&PrvStat), &lPrv);
    RegCloseKey(hKey);

    RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile", 0, KEY_READ, &hKey);
    RegQueryValueExW(hKey, L"EnableFirewall", nullptr, nullptr, reinterpret_cast<LPBYTE>(&PubStat), &lPub);
    RegCloseKey(hKey);

    if (DomStat == 1) {
        print::set_text(("Domain Network : Enabled \n"), Green);

    }
    else {
        print::set_text(("Domain Network : Disabled \n"), Red);

    }
    if (PrvStat == 1) {
        print::set_text(("Private Network : Enabled \n"), Green);

    }
    else {
        print::set_text(("Private Network : Disabled \n"), Red);

    }
    if (PubStat == 1) {
        print::set_text(("Public Network : Enabled \n"), Green);

    }
    else {
        print::set_text(("Public Network : Disabled \n"), Red);

    }
    RegCloseKey(hKey);

}

void Winver()
{
    HKEY hKey;
    char winver[256];
    char buildnumber[256];
    DWORD ubr = 0;

    DWORD lwinver = sizeof(winver);
    DWORD lbuildnumber = sizeof(buildnumber);
    DWORD lubr = sizeof(ubr);

    RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey);
    RegQueryValueEx(hKey, "DisplayVersion", nullptr, nullptr, (LPBYTE)winver, &lwinver);
    RegQueryValueEx(hKey, "CurrentBuildNumber", nullptr, nullptr, (LPBYTE)buildnumber, &lbuildnumber);
    RegQueryValueEx(hKey, "UBR", nullptr, nullptr, (LPBYTE)&ubr, &lubr);

    std::cout << "Windows version: " << winver << "(" << buildnumber << "." << ubr << ")" << std::endl;
}

void CPUInfo() {

    int cpuinfo[4] = { 0 };
    char model[49] = { 0 };

    for (int i = 0; i < 3; ++i) {
        __cpuid(cpuinfo, 0x80000002 + i);
        std::memcpy(model + i * 16, cpuinfo, 16);
    }
    std::cout << "CPU : " << model << "\n";
}

void GPUInfo() {
    const std::string getgpu = "powershell -command \"Get-WmiObject Win32_VideoController | Select-Object -ExpandProperty Name\"";

    std::array<char, 128> GPU;
    std::string GPUName;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(getgpu.c_str(), "r"), _pclose);

    while (fgets(GPU.data(), GPU.size(), pipe.get()) != nullptr) {
        GPUName += GPU.data();
    }

    std::cout << "GPU : " << GPUName;

}

void MBInfo() {
    const std::string getmbinfo = "powershell -command \"Get-WmiObject Win32_BaseBoard | Format-Table -Property Manufacturer, Product -HideTableHeaders\"";
    std::array<char, 128> MB;
    std::string MBInfoN;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(getmbinfo.c_str(), "r"), _pclose);

    while (fgets(MB.data(), MB.size(), pipe.get()) != nullptr) {
        MBInfoN += MB.data();
    }

    std::istringstream stream(MBInfoN);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty()) {
            std::cout << "MB :  " << line << "\n";
        }
    }
}

void VGKStat()
{
    std::string vgk = "sc query vgk > nul";

    if (system(vgk.c_str()) == 0) {

        print::set_text(("Vanguard : Enabled \n"), Green);

    }
    else {
        print::set_text(("Vanguard : Disabled \n"), Red);
    }

}

void FaceitStat() {
    std::string faceitService = "sc query FaceitAC > nul ";


    if (system(faceitService.c_str()) == 0) {
        print::set_text(("Faceit : Enabled \n"), Green);
    }
    else {
        print::set_text(("Faceit : Disabled \n"), Red);
    }
}

int main() {

    SetConsoleTitleA("Check Info - By Loyd");
    HWND consoleWindow = GetConsoleWindow();
    LONG style = GetWindowLong(consoleWindow, GWL_STYLE);
    style &= ~(WS_MAXIMIZEBOX) & ~(WS_THICKFRAME);
    SetWindowLong(consoleWindow, GWL_STYLE, style);
    system("mode con: cols=68 lines=33");

    print::set_text(("  ______ __                __           _______         ___        \n"), LightCyan);
    print::set_text((" |      |  |--.-----.----.|  |--.      |_     _|.-----.'  _|.-----.\n"), LightCyan);
    print::set_text((" |   ---|     |  -__|  __||    <        _|   |_ |     |   _||  _  |\n"), LightCyan);
    print::set_text((" |______|__|__|_____|____||__|__|      |_______||__|__|__|  |_____|\n\n\n\n"), LightCyan);

    print::set_text(("==Security==\n\n"), Yellow);

    SBStat();
    TPMStat();
    HVCIStat();
    VT();
    VBSStat();
    RTPStat();

    print::set_text(("\n==Firewall==\n\n"), Yellow);

    FirewallStat();

    print::set_text(("\n==System Information==\n\n"), Yellow);

    Winver();
    CPUInfo();
    GPUInfo();
    MBInfo();

    print::set_text(("\n==Anti Cheat==\n\n"), Yellow);

    VGKStat();
    FaceitStat();

    std::cin.get();

}
