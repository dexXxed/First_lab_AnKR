#include <iostream>
#include <Windows.h>
#include <wincrypt.h>
#include <vector>
#include <algorithm>
#include <iomanip>
using namespace std;


class descriptive_exception : public exception {
public:
    explicit descriptive_exception(const char *message) : msg_(message) {}

    char const *what() const noexcept override { return msg_; }

private:
    const char *msg_;
};

struct st_prov {
    DWORD prov_type;
    LPSTR name;
};


bool try_get_providers(int index, vector<st_prov> &list) {
    DWORD byte_count, tmp;

    if (!CryptEnumProviders(index, nullptr, 0, &tmp, nullptr, &byte_count)) {
        if (GetLastError() == ERROR_NO_MORE_ITEMS)
            cout << "Got the end of a list (1)" << endl;
        else
            throw descriptive_exception("Error 1 in try_get_providers");
        return false;
    }

    st_prov prov{};
    prov.name = new char[byte_count];

    if (!CryptEnumProviders(index, nullptr, 0, &(prov.prov_type), prov.name,
                            &byte_count)) {
        if (GetLastError() == ERROR_NO_MORE_ITEMS)
            cout << "Got the end of a list (2)" << endl;
        else
            throw descriptive_exception("Error 2 in try_get_providers");
        return false;
    }

    list.push_back(prov);

    return true;
}

void get_csp_containers(HCRYPTPROV handle, vector<string> &mas) {
    char buff[512];
    DWORD tmp;

    if (!CryptGetProvParam(handle, PP_ENUMCONTAINERS, (BYTE *) &buff, &tmp, CRYPT_FIRST))
        cout << "In start reading containers" << endl;

    mas.emplace_back(buff);

    while (CryptGetProvParam(handle, PP_ENUMCONTAINERS, (BYTE *) &buff, &tmp, CRYPT_NEXT))
        mas.emplace_back(buff);

    if (GetLastError() != ERROR_NO_MORE_ITEMS)
        cout << "In start reading containers" << endl;
}

bool name_in_array(const string &name, const vector<string> &mas) {
    for (const string &a : mas)
        if (a == name)
            return true;
    return false;
}

void get_information_about_csp(const DWORD csp_type_code, LPSTR csp_name, vector<pair<PROV_ENUMALGS_EX, DWORD>> &map,
                               const string &keycase_name) {
    HCRYPTPROV handle;
    vector<string> containers;

    wcout << "Begin work with [" << csp_type_code << "] " << (LPCTSTR) (csp_name) << endl;

    if (!CryptAcquireContext(&handle, nullptr, reinterpret_cast<LPCSTR>(reinterpret_cast<LPCWSTR>(csp_name)),
                             csp_type_code, 0)) {
        if (GetLastError() == NTE_BAD_KEYSET) {
            cout << "Creating " << keycase_name << " keycontainer" << endl;

            CryptReleaseContext(handle, 0);

            if (!CryptAcquireContext(&handle, keycase_name.c_str(), csp_name, csp_type_code, CRYPT_NEWKEYSET)) {
                if (GetLastError() == NTE_EXISTS) {
                    cout << "Key set " << keycase_name << " already exists, trying to open" << endl;
                    cout << "keycontainer " << keycase_name << " already exist" << endl;
                    CryptReleaseContext(handle, 0);

                    if (!CryptAcquireContext(&handle,
                                             keycase_name.c_str(),
                                             reinterpret_cast<LPCSTR>(csp_name), csp_type_code, 0))
                        throw descriptive_exception("In get_information_about_csp with existing key container");

                } else
                    throw descriptive_exception("In get csp handle with create key container");
            }
        } else
            cout << "In get_information_about_csp with 0 dwFlags" << endl;
    }

    get_csp_containers(handle, containers);

    if (name_in_array(keycase_name, containers)) {
        cout << "Keycontainer " << keycase_name << " already exists" << endl;

        CryptReleaseContext(handle, 0);

        if (!CryptAcquireContext(&handle, (keycase_name.c_str()),
                                 reinterpret_cast<LPCSTR> (csp_name), csp_type_code, 0))
            throw descriptive_exception("In get_information_about_csp with existing key container");
    }


    PROV_ENUMALGS_EX param;
    DWORD param2,
            param_size = sizeof(param),
            param2_size = sizeof(param2);


    if (!CryptGetProvParam(handle, PP_ENUMALGS_EX, (BYTE *) &param, &param_size, CRYPT_FIRST))
        cout << "In starting reading algorithms: PP_ENUMALGS_EX" << endl;

    if (!CryptGetProvParam(handle, PP_KEYX_KEYSIZE_INC, (BYTE *) &param2, &param2_size, CRYPT_FIRST))
        cout << "In starting reading algorithms: PP_KEYX_KEYSIZE_INC" << endl;

    map.emplace_back(pair<PROV_ENUMALGS_EX, DWORD>(param, param2));

    while (CryptGetProvParam(handle, PP_ENUMALGS_EX, (BYTE *) &param, &param_size, CRYPT_NEXT) &&
           CryptGetProvParam(handle, PP_KEYX_KEYSIZE_INC, (BYTE *) &param2, &param2_size, 0)) {
        if (param2) {
            map.emplace_back(pair<PROV_ENUMALGS_EX, DWORD>(param, param2));
        }
    }


    if (GetLastError() != ERROR_NO_MORE_ITEMS)
        cout << "In reading algorithms" << endl;

    sort(map.begin(), map.end(),
         [](pair<PROV_ENUMALGS_EX, DWORD> const &a, pair<PROV_ENUMALGS_EX, DWORD> const &b) {
             return GET_ALG_CLASS(a.first.aiAlgid) < GET_ALG_CLASS(b.first.aiAlgid);
         });

    CryptReleaseContext(handle, 0);
}

void print_information_about_csp(const DWORD csp_type, LPSTR csp_name, vector<pair<PROV_ENUMALGS_EX, DWORD>> &mas) {
    cout << "+" << setw(123) << setfill('-') << "" << "+" << endl;
    cout << "|Type: " << setw(26) << setfill(' ') << left << csp_type << "Name: " << setw(85) << csp_name << "|"
         << endl;
    cout << setfill('-') << "+" << setw(40) << "" << "+" << setw(15) << "" << "+" << setw(17) << "" << "+" << setw(10)
         << "" << "+" << setw(10) << "" << "+" << setw(10) << "" << "+" << setw(15) << "" << "+" << endl;
    cout << setfill(' ') << setw(41) << "|#Algorithm Name" << setw(16) << "|#Algorithm ID" << setw(18)
         << "|#Algorithm Class" << setw(11) << "|#def len" << setw(11) << "|#min len" << setw(11) << "|#max len"
         << setw(16) << "|#keysize inc" << "|"
         << endl;
    int One_time_flag = 0;
    for (auto &it : mas) {
        if (GetLastError() != ERROR_INVALID_PARAMETER) {
            if (it.first.aiAlgid != 0xcccccccc) {
                wcout << "|" << left << setw(40) << it.first.szLongName;
                cout << "|" << setw(15) << it.first.aiAlgid;
                cout << "|" << setw(17);
                switch (GET_ALG_CLASS(it.first.aiAlgid)) {
                    case ALG_CLASS_ALL:
                        cout << "ALL";
                        break;
                    case ALG_CLASS_ANY:
                        cout << "ANY";
                        break;
                    case ALG_CLASS_DATA_ENCRYPT:
                        cout << "DATA_ENCRYPT";
                        break;
                    case ALG_CLASS_HASH:
                        cout << "HASH";
                        break;
                    case ALG_CLASS_KEY_EXCHANGE:
                        cout << "KEY_EXCHANGE";
                        break;
                    case ALG_CLASS_MSG_ENCRYPT:
                        cout << "MSG_ENCRYPT";
                        break;
                    case ALG_CLASS_SIGNATURE:
                        cout << "SIGNATURE";
                        break;
                }
                cout << "|" << setw(10) << it.first.dwDefaultLen;
                cout << "|" << setw(10) << it.first.dwMinLen;
                cout << "|" << setw(10) << it.first.dwMaxLen;
                if (it.second == 0xcccccccc)
                    cout << "|" << setw(15) << "No info" << setw(10) << "|" << endl;
                else
                    cout << "|" << setw(15) << it.second << setw(10) << "|" << endl;
            }
        } else {
            if (One_time_flag == 0)
                cout << "|" << setw(123) << setfill(' ') << left
                     << "No information! (Maybe there is no hardware supporting)" << "|" << endl;
            One_time_flag++;
        }
    }
    cout << setfill('-') << "+" << setw(40) << "" << "+" << setw(15) << "" << "+" << setw(17) << "" << "+" << setw(10)
         << "" << "+" << setw(10) << "" << "+" << setw(10) << "" << "+" << setw(15) << "" << "+" << endl;
}


void get_csp_handler(DWORD csp_type, LPTSTR csp_name, LPCTSTR container_name, HCRYPTPROV &handler) {

    if (!CryptAcquireContext(&handler, container_name, csp_name, csp_type, 0)) {
        if (GetLastError() == NTE_BAD_KEYSET) {
            wcout << "Creating " << container_name << " key container" << endl;
            CryptReleaseContext(handler, 0);

            if (!CryptAcquireContext(&handler, container_name, csp_name, csp_type, CRYPT_NEWKEYSET)) {

                if (GetLastError() == NTE_EXISTS) {
                    CryptReleaseContext(handler, 0);

                    if (!CryptAcquireContext(&handler, container_name, csp_name, csp_type, 0))
                        throw descriptive_exception("In get_csp_handler with existing key container");

                } else {
                    throw descriptive_exception("In get_csp_handler with creating key container");
                }

            }

        } else {
            throw descriptive_exception("In get_csp_handler with zero dwFlags (0)");
        }
    } else {
        wcout << "A cryptographic context with the " << container_name << " key container has been acquired." << endl;
    }

}

int main() {
    HCRYPTPROV hCryptProv; // Handle for the cryptographic provider context.
    DWORD csp_type = PROV_RSA_FULL;
    auto csp_name = (LPTSTR) MS_STRONG_PROV;

    string name;
    cout << "Enter name of container, which will be created: ";
    cin >> name;

    LPCTSTR container_name = TEXT(name.c_str()); // The name of the container.
    vector<st_prov> providers;

    try {
        get_csp_handler(csp_type, csp_name, container_name, hCryptProv);

        cout << "Start reading CSPs" << endl;

        for (int i = 0; try_get_providers(i, providers); ++i);
        sort(providers.begin(), providers.end(),
             [](const st_prov &a, const st_prov &b) { return a.prov_type < b.prov_type; });
        cout << "CSPs were read!" << endl;

        vector<pair<PROV_ENUMALGS_EX, DWORD>> map;

        for (const st_prov &prov : providers) {
            cout << endl << endl;
            get_information_about_csp(prov.prov_type, prov.name, map, name);
            print_information_about_csp(prov.prov_type, prov.name, map);
        }


        system("PAUSE");
        return 0;
    }
    catch (exception &error) {
        cout << "Error message: " << error.what() << endl;
        cout << "System Error Code: " << GetLastError() << endl;
        cout << "You can read more about System Error Codes here:" <<
             "https://docs.microsoft.com/ru-ru/windows/win32/debug/system-error-codes" << endl;
        system("PAUSE");
        return -1;
    }

}