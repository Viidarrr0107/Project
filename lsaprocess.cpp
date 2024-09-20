#include <iostream>
#include <windows.h>
#include <sddl.h>
#include <ntsecapi.h>
#include <aclapi.h>
#include <ntstatus.h>
#include <vector>
#pragma comment(lib, "advapi32.lib")

using namespace std;

LPCSTR ConvertWCharToLPCSTR(const wchar_t* wideString) {
    int bufferSize = WideCharToMultiByte(CP_ACP, 0, wideString, -1, NULL, 0, NULL, NULL);
    char* multiByteString = new char[bufferSize];
    WideCharToMultiByte(CP_ACP, 0, wideString, -1, multiByteString, bufferSize, NULL, NULL);
    return multiByteString;
}

int GetSIDInformation(wchar_t* accountName, LSA_HANDLE policyHandle, PSID* accountSID) {
    if (accountName == L"system"){
        ConvertStringSidToSidW(L"S-1-5-18", accountSID);
    }
    else {
        PLSA_REFERENCED_DOMAIN_LIST domainList;
        PLSA_TRANSLATED_SID2 sidList;
        LSA_UNICODE_STRING targetSystem;
        targetSystem.Buffer = accountName;
        targetSystem.Length = wcslen(accountName) * sizeof(wchar_t);
        targetSystem.MaximumLength = targetSystem.Length + sizeof(wchar_t);

        NTSTATUS status = LsaLookupNames2(policyHandle, 0, 1, &targetSystem, &domainList, &sidList);
        if (status != STATUS_SUCCESS) {
            wcerr << L"LsaLookupNames failed: " << LsaNtStatusToWinError(status) << endl;
            LsaClose(policyHandle);
            return 1;
        }

        if (sidList->Use != SidTypeUnknown) {
            *accountSID = sidList->Sid;
        } else {
            wcerr << L"SID not found for account: " << accountName << endl;
            LsaFreeMemory(domainList);
            LsaFreeMemory(sidList);
            LsaClose(policyHandle);
            return 1;
        }

        LsaFreeMemory(domainList);
        LsaFreeMemory(sidList);
    }    
    
    return 0;
}

bool InitLsaString(PLSA_UNICODE_STRING LsaString, LPCWSTR String) {
    DWORD StringLength;

    if (String == NULL) {
        return FALSE;
    }

    StringLength = wcslen(String);
    if (StringLength > 0x7ffe) {
        return FALSE;
    }

    LsaString->Buffer = (PWSTR)String;
    LsaString->Length = (USHORT)StringLength * sizeof(WCHAR);
    LsaString->MaximumLength = (USHORT)(StringLength + 1) * sizeof(WCHAR);

    return TRUE;
}

void ModifyPrivileges(PSID accountSID, LPCWSTR priv, LSA_HANDLE policyHandle, HANDLE hToken, bool enable) {
    LSA_UNICODE_STRING lucPrivilege;
    NTSTATUS ntsResult;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!InitLsaString(&lucPrivilege, priv)) {
        wcout << L"Failed InitLsaString" << endl;
        return;
    }

    if (!LookupPrivilegeValue(NULL, priv, &luid)) {
        cout << "LookupPrivilegeValue error: " << GetLastError() << endl;
    }    

    if (enable) {
        ntsResult = LsaAddAccountRights(policyHandle, accountSID, &lucPrivilege, 1);
        if (ntsResult == STATUS_SUCCESS) {
            wcout << L"LSA Privilege added."  << endl;
        }
        else if (ntsResult == STATUS_NO_SUCH_PRIVILEGE) {
            wcout << L"LSA" << priv << " was not added - " << LsaNtStatusToWinError(ntsResult) << L"privilege name does not exist" << endl;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
            wcout << L"AdjustTokenPrivileges error: " << GetLastError() << endl;
        }
        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
            wcout << L"The token does not have the specified privilege." << endl;
        }
    }
    else {        
        ntsResult = LsaRemoveAccountRights(policyHandle, accountSID, FALSE, &lucPrivilege, 1);
        if (ntsResult == STATUS_SUCCESS) {
            wcout << L"LSA Privilege removed."  << endl;
        }
        else if (ntsResult == STATUS_NO_SUCH_PRIVILEGE) {
            wcout << L"LSA " << priv << L" was not removed - " << LsaNtStatusToWinError(ntsResult) << L"privilege name does not exist" << endl;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
            wcout << L"AdjustTokenPrivileges error: " << GetLastError() << endl;
        }
        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
            wcout << L"The token does not have the specified privilege." << endl;
        }
    }
}

bool DisableAbusivePrivileges(PSID accountSID, LSA_HANDLE policyHandle, HANDLE hToken) {
    vector<LPCWSTR> privileges = {
        SE_IMPERSONATE_NAME,
        SE_ASSIGNPRIMARYTOKEN_NAME,
        SE_TCB_NAME,
        SE_BACKUP_NAME,
        SE_RESTORE_NAME,
        SE_CREATE_TOKEN_NAME,
        SE_LOAD_DRIVER_NAME,
        SE_TAKE_OWNERSHIP_NAME,
        SE_DEBUG_NAME
    };

    for (LPCWSTR priv : privileges) {
        ModifyPrivileges(accountSID, priv, policyHandle, hToken, false);   
    }
    return true;
}

void EnumeratePrivileges(PSID AccountSID, LSA_HANDLE PolicyHandle) {
    PLSA_UNICODE_STRING userRights;
    ULONG countOfRights;
    NTSTATUS ntsResult;

    ntsResult = LsaEnumerateAccountRights(PolicyHandle, AccountSID, &userRights, &countOfRights);

    if (ntsResult == STATUS_SUCCESS) {
        wcout << L"LSA Privileges assigned to the account:" << endl;
        for (ULONG i = 0; i < countOfRights; i++) {
            wcout << userRights[i].Buffer  << endl;
        }
        wcout << endl;
        LsaFreeMemory(userRights);
    }
    else if (ntsResult == STATUS_OBJECT_NAME_NOT_FOUND ) {
        wcout << L"LsaEnumerateAccountRights failed, no privilege found - " << LsaNtStatusToWinError(ntsResult) << endl;
    }
}

bool CheckProcessPrivilege(HANDLE hToken, LPCWSTR priv) {
    LUID luid;
    if (!LookupPrivilegeValue(NULL, priv, &luid)) {
        cout << "LookupPrivilegeValue error: " << GetLastError() << endl;
        return false;
    }

    PRIVILEGE_SET privilegeSet;
    privilegeSet.PrivilegeCount = 1;
    privilegeSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privilegeSet.Privilege[0].Luid = luid;
    privilegeSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL bResult;
    if (!PrivilegeCheck(hToken, &privilegeSet, &bResult)) {
        cout << "Process PrivilegeCheck error: " << GetLastError() << endl;
        return false;
    }

    return bResult;
}

void ListPrivileges(HANDLE hToken) {
    vector<LPCWSTR> privileges = {
        SE_ASSIGNPRIMARYTOKEN_NAME,
        SE_AUDIT_NAME,
        SE_BACKUP_NAME,
        SE_CHANGE_NOTIFY_NAME,
        SE_CREATE_GLOBAL_NAME,
        SE_CREATE_PAGEFILE_NAME,
        SE_CREATE_PERMANENT_NAME,
        SE_CREATE_SYMBOLIC_LINK_NAME,
        SE_CREATE_TOKEN_NAME,
        SE_DEBUG_NAME,
        SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME,
        SE_ENABLE_DELEGATION_NAME,
        SE_IMPERSONATE_NAME,
        SE_INC_BASE_PRIORITY_NAME,
        SE_INCREASE_QUOTA_NAME,
        SE_INC_WORKING_SET_NAME,
        SE_LOAD_DRIVER_NAME,
        SE_LOCK_MEMORY_NAME,
        SE_MACHINE_ACCOUNT_NAME,
        SE_MANAGE_VOLUME_NAME,
        SE_PROF_SINGLE_PROCESS_NAME,
        SE_RELABEL_NAME,
        SE_REMOTE_SHUTDOWN_NAME,
        SE_RESTORE_NAME,
        SE_SECURITY_NAME,
        SE_SHUTDOWN_NAME,
        SE_SYNC_AGENT_NAME,
        SE_SYSTEM_ENVIRONMENT_NAME,
        SE_SYSTEM_PROFILE_NAME,
        SE_SYSTEMTIME_NAME,
        SE_TAKE_OWNERSHIP_NAME,
        SE_TCB_NAME,
        SE_TIME_ZONE_NAME,
        SE_TRUSTED_CREDMAN_ACCESS_NAME,
        SE_UNDOCK_NAME
    };

    for (const auto& privilege : privileges) {
        if (CheckProcessPrivilege(hToken, privilege)) {
            wcout << L"Process Privilege held: " << privilege << endl;
        }
        else {
            wcout << L"Process Privilege NOT held: " << privilege << endl;
        }
    }
}

bool RefreshUserPrivileges(LPCWSTR username) {
    // Run gpupdate /force to refresh Group Policy
    if (system("gpupdate /force") != 0) {
        wcout << "Failed to run gpupdate /force."  << endl;
        return false;
    }

    wcout << "User privileges refreshed successfully." << endl;
    return true;
}

HANDLE GetUserToken(const wstring& username) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        cout << "OpenProcessToken error: " << GetLastError() << endl;
    }

    return hToken;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        wcout << L"Usage: " << argv[0] << L" <list|modify|disableabusive|refresh> <Username> [<Privilege> <enabled|disabled>]" << endl;
        return 1;
    }
    // 1. Initialize policy handle
    LSA_OBJECT_ATTRIBUTES objectAttributes;
    ZeroMemory(&objectAttributes, sizeof(objectAttributes));

    LSA_HANDLE policyHandle;
    NTSTATUS status = LsaOpenPolicy(NULL, &objectAttributes, POLICY_ALL_ACCESS, &policyHandle);
    if (status != STATUS_SUCCESS) {
        wcerr << L"LsaOpenPolicy failed with error: " << LsaNtStatusToWinError(status) << endl;
        return 1;
    }

    // 2. Initialize token
    HANDLE hToken = GetUserToken(argv[2]);
    if (!hToken) {
        return 1;
    }

    PSID accountSID = NULL;
    if (GetSIDInformation(argv[2], policyHandle, &accountSID) == 0) {
        if (_wcsicmp(argv[1], L"list") == 0) {
            wcout << L"Listing LSA User Rights Privileges" << endl;
            wcout << L"-------------------------------------" << endl;
            EnumeratePrivileges(accountSID, policyHandle);
            wcout << L"Listing Process Token Privileges" << endl;
            wcout << L"-------------------------------------" << endl;
            ListPrivileges(hToken);
        }
        else if (_wcsicmp(argv[1], L"modify") == 0 && argc == 5) {
            bool enable = _wcsicmp(argv[4], L"enabled") == 0;
            wcout << L"Modifying LSA User Rights and Process Privileges" << endl;
            wcout << L"------------------------------------" << endl;
            ModifyPrivileges(accountSID, argv[3], policyHandle, hToken, enable);
            RefreshUserPrivileges(argv[2]);
            wcout << L"Listing LSA User Rights Privileges" << endl;
            wcout << L"-------------------------------------" << endl;
            EnumeratePrivileges(accountSID, policyHandle);
            wcout << L"Listing Process Token Privileges" << endl;
            wcout << L"------------------------------------" << endl;
            ListPrivileges(hToken);
        }
        else if (_wcsicmp(argv[1], L"disableabusive") == 0) {
            if (DisableAbusivePrivileges(accountSID, policyHandle, hToken)) {
                wcout << L"Abusive privileges disabled successfully." << endl;
            }
            else {
                wcout << L"Failed to disable abusive privileges." << endl;
            }
            EnumeratePrivileges(accountSID, policyHandle);
        }
        else if (_wcsicmp(argv[1], L"refresh") == 0) {
            if (RefreshUserPrivileges(argv[2])) {
                wcout << L"User privileges refreshed successfully." << endl;
            }
            else {
                wcout << L"Failed to refresh user privileges." << endl;
            }
        }
        else {
            wcout << L"Usage: " << argv[0] << L" <list|modify|disableabusive|refresh> <Username> [<Privilege> <enabled|disabled>]" << endl;
        }
    }
    // RefreshUserPrivileges(argv[2]);
    system("whoami /priv");
    // system("PrintSpoofer.exe -i -c cmd");
    LsaClose(policyHandle);
    return 0;
}
