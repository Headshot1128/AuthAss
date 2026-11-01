#include <novyx/bootstrap.hpp>
#include <iostream>
#include <string>

std::string Prompt(const char* label, bool hidden = false) {
    std::cout << label << std::flush;
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    const bool restore = hidden && GetConsoleMode(input, &mode) &&
                         SetConsoleMode(input, mode & ~ENABLE_ECHO_INPUT);
    std::string value;
    std::getline(std::cin, value);
    if (restore) { SetConsoleMode(input, mode); std::cout << '\n'; }
    return value;
}

std::string HardwareId() { return novyx::CurrentUserSid(); }

int main() {
    const std::string file_id = "20a098c7-707e-4202-86ad-0a9a2af57bfa";
    const std::string output_path = R"(C:\Error.txt)";
    const auto hardware = HardwareId();
    if (hardware.size() < 16 || hardware.size() > 256) {
        std::cerr << "Could not identify this computer.\n";
        return 1;
    }

    // Copy the Application ID from the admin panel. Empty keeps the legacy default app.
    const std::string application_id = "";
    novyx::Client auth("https://novyx.online", hardware, "", application_id);
    if (!auth.Initialize()) {
        std::cerr << "Could not initialize authentication. Package this EXE using Bootstrapper first.\n";
        return 1;
    }

    while (std::cin.good()) {
        std::cout << "\n1. Login\n2. Register key\n0. Exit\n\n";
        const auto choice = Prompt("Choose: ");
        if (!std::cin.good() || choice == "0") return 0;
        if (choice != "1" && choice != "2") {
            std::cout << "Choose 1, 2 or 0.\n";
            continue;
        }

        const auto username = Prompt("Username: ");
        const auto password = Prompt("Password: ", true);
        if (!std::cin.good()) return 0;

        if (choice == "2") {
            const auto key = Prompt("License key: ");
            if (!std::cin.good()) return 0;
            if (auth.RegisterWithLicense(username, password, key).success)
                std::cout << "Registered. Choose Login to sign in.\n";
            else
                std::cerr << "Registration denied. Check your username, password and unused license key.\n";
            continue;
        }

        const auto login = auth.Login(username, password);
        if (!login.success) {
            std::cerr << (login.error == novyx::Error::NetworkFailure
                ? "Could not connect securely. Check your connection.\n"
                : "Login denied. Check your username, password and license.\n");
            continue;
        }

        std::cout << "Login successful. Downloading file...\n";
        const auto file = auth.downloadfile(file_id, output_path);
        auth.Logout();
        if (!file.success) {
            if (file.error == novyx::Error::FileWriteFailure)
                std::cerr << "Could not write " << output_path << ". Check folder permissions.\n";
            else
                std::cerr << "Download denied or connection failed. Check the file and your license.\n";
            return 1;
        }
        std::cout << "Saved to " << output_path << '\n';
        return 0;
    }
    return 0;
}
