#include <iostream>
#include <string>

struct zzz_string {
    unsigned long long length;
    char* data;
};

zzz_string z_str;
std::string *s_str;

static void dump(const char *tag) {
    std::cerr << tag
              << " z_len=" << std::hex << z_str.length
              << " z_data=" << (void*)z_str.data
              << " s_obj=" << (void*)s_str;
    if (s_str) {
        std::cerr << " s_data=" << (void*)s_str->data()
                  << " s_size=" << s_str->size()
                  << " s_cap=" << s_str->capacity();
    }
    std::cerr << std::dec << std::endl;
}

int main() {
    int choice = 0;
    while (1) {
        std::cout << "> ";
        std::cin >> choice;
        if (!std::cin.good()) break;
        if (choice == 1) {
            std::cout << "Length: ";
            std::cin >> z_str.length;
            std::cin.ignore(1, '\n');
            if (z_str.data) delete z_str.data;
            z_str.data = new char[z_str.length + 1];
            std::cout << "Data: ";
            std::cin.read(z_str.data, z_str.length);
            dump("new_z");
        } else if (choice == 2) {
            if (s_str) delete s_str;
            s_str = new std::string();
            std::cout << "Data: ";
            std::cin >> *s_str;
            dump("new_s");
        } else if (choice == 3) {
            if (!z_str.data) continue;
            if (!s_str) s_str = new std::string();
            *s_str = z_str.data;
            s_str->data()[z_str.length] = '\0';
            dump("move");
        } else {
            break;
        }
    }
}
