#include "accountactions.h"
#include "statusdefs.h"
#include "utils.h"
#include "passwordgenerator.h"

#include <iostream>
#include <string>
#include <vector>

#include <QString>
#include <QClipboard>
#include <QGuiApplication>


//non member functions
std::string getPassword(AccountsStore &);

bool modifyGeneralSettings(Settings &);
bool modifyDatabaseSettings(Settings &);
bool modifyGeneratorSettings(Settings &);
bool modifySyncSettings(AccountsStore &);

bool getBoolChoice();
void modifyAllowedCharacters(PasswordGenerator &, bool);


AccountActions::AccountActions(AccountsStore *s)
{
    store = s;

    connect(store, &AccountsStore::readyMessage, [=](const QString &msg) {
        std::cout << "Testing Receive message: " << msg.toStdString() << std::endl;
    });
}

void AccountActions::addAccount(AccountsStore &store)
{
    std::cout << "-- Add Account --" << std::endl;
    std::string accountName, userName, passWord, url;
    std::cout << "Enter Account Name: ";
    std::getline(std::cin, accountName);
    std::cout << "Enter username: ";
    std::getline(std::cin, userName);
    std::cout << "Enter URL: ";
    std::getline(std::cin, url);
    std::cout << std::endl;

    try {
        passWord = getPassword(store);
    } catch (...) {
        return;
    }

    StatusDefs::Account_Status status = store.addAccount(new Account{QString::fromStdString({accountName}),
                                                                     QString::fromStdString({userName}),
                                                                     QString::fromStdString({passWord}),
                                                                     QString::fromStdString({passWord}),
                                                                     QString::fromStdString({url})});

    if (status != StatusDefs::Account_Status::success) {
        std::cout << "->Failed to add: " << StatusDefs::get_Account_Status(status) << std::endl;
    } else {
        std::cout << "->Account added" << std::endl;
    }
}


bool AccountActions::deleteAccount(AccountsStore &store)
{
    listAccounts(store);

    int account = -1;
    do {
        std::cout << "Enter account Number to delete, or [" << store.getNumberOfAccounts()+1 << "] to go back: ";
        account = Utils::getSelectionAsInt(1, store.getNumberOfAccounts()+1);
    } while (account == -1);

    if (account == store.getNumberOfAccounts()+1)
        return false;

    StatusDefs::Account_Status status = store.deleteAccount(store.getAccounts()[account-1]);

    if (status == StatusDefs::Account_Status::not_found) {
        std::cout << "Account not found" << std::endl;
        return false;
    } else {
        return true;
    }
}


void AccountActions::copyPassword(AccountsStore &store)
{
    listAccounts(store);
    int account = Utils::getSelectionAsInt(1, store.getNumberOfAccounts(),
                                           "Enter account Number to get password: ");

    int pass = -1;
    do {
        std::cout << "Enter 1 for current password, or 2 for old password: ";
        pass = Utils::getSelectionAsInt(1,2);
    } while (pass == -1);

    QString username = store.getAccounts()[account-1]->getUserName();

    try {
        std::string password = (pass == 1) ? store.getPassword(store.getAccounts()[account-1]) :
                                             store.getOldPassword(store.getAccounts()[account-1]);

        QString url = store.getAccounts()[account-1]->getUrl();
        qDebug() << QString{"For testing, password:%1, username:%2, url:%3"}.arg(QString::fromStdString(password)).arg(username).arg(url);

    } catch (EncryptionException &ex) {
        std::cout << "\nError Decrypting password: " << ex.what() << std::endl;
        qDebug() << ex.what();
    }
}


void AccountActions::editAccount(AccountsStore &store)
{
    listAccounts(store);
    int account = -1;
    do {
        std::cout << "Enter account Number to edit: ";
        account = Utils::getSelectionAsInt(1, store.getNumberOfAccounts());
    } while (account == -1);

    Account *act = store.getAccounts()[--account];
    std::cout << "\nAccount:" << std::endl;
    std::cout << "Name: " << act->getAccountName().toStdString() << std::endl;
    std::cout << "Username: " << act->getUserName().toStdString() << std::endl;
    std::cout << "URL: " << act->getUrl().toStdString() << std::endl << std::endl;

    std::cout << "Options:" << std::endl;
    std::cout << "1. Change username" << std::endl;
    std::cout << "2. Change URL" << std::endl;
    std::cout << "3. Change password" << std::endl;
    std::cout << "4. Go back" << std::endl;

    int choice = -1;
    do {
        std::cout << "Enter Choice: ";
        choice = Utils::getSelectionAsInt(1, 4);
    } while (choice == -1);


    switch (choice) {
    case 1:
    {
        std::cout << "Enter new username: ";
        std::string username;
        std::getline(std::cin, username);
        act->setUserName(QString::fromStdString(username));
        StatusDefs::Account_Status status = store.updateAccount(act);
        std::cout << StatusDefs::get_Account_Status(status) << std::endl;
        break;
    }
    case 2:
    {
        std::cout << "Enter new URL: ";
        std::string url;
        std::getline(std::cin, url);
        act->setUrl(QString::fromStdString(url));
        StatusDefs::Account_Status status = store.updateAccount(act);
        std::cout << StatusDefs::get_Account_Status(status) << std::endl;
        break;
    }
    case 3:
    {
        std::string passWord{""};
        try {
            passWord = getPassword(store);
        } catch (...) {
            return;
        }

        act->setPassword(QString::fromStdString(passWord));
        StatusDefs::Account_Status status = store.updateAccount(act);
        std::cout << StatusDefs::get_Account_Status(status) << std::endl;
        break;
    }
    case 4:
        // do nothing
        break;
    default:
        std::cout << "Invalid Selection" << std::endl;
        break;
    }
}


void AccountActions::listAccounts(AccountsStore &accounts)
{
    bool showKeyError{false};
    std::cout << std::endl;
    std::cout << "-- Accounts --" << std::endl;
    int i{1};

    for (Account *account : accounts.getAccounts())
        if (!account->getDeleted()) {
            std::cout << i++ << ". " << account->getAccountName().toStdString();

            if (!account->getCorrectKey()) {
                showKeyError = true;
                std::cout << "  *" << std::endl;
            } else {
                std::cout << std::endl;
            }
        }

    if (showKeyError)
        std::cout << "* = accounts whose current password could not be decrypted with current key." << std::endl;

    std::cout << std::endl;
}


void AccountActions::editSettings(AccountsStore &store)
{
    showSettings(store);
    std::cout << std::endl;

    std::cout << "Options:" << std::endl;
    std::cout << "1. Change General Settings" << std::endl;
    std::cout << "2. Change Generator Settings" << std::endl;
    std::cout << "3. Change Database Settings" << std::endl;
    std::cout << "4. Change Sync Settings" << std::endl;
    std::cout << "5. Back" << std::endl;

    bool chkSave{false};
    int choice = -1;
    do {
        std::cout << "Enter Choice: ";
        choice = Utils::getSelectionAsInt(1, 5);
    } while (choice == -1);

    switch (choice) {
    case 1:
        chkSave = modifyGeneralSettings(store.getSettings());
        break;
    case 2:
        chkSave = modifyGeneratorSettings(store.getSettings());
        break;
    case 3:
        chkSave = modifyDatabaseSettings(store.getSettings());
        break;
    case 4:
        chkSave = modifySyncSettings(store);
        break;
    case 5:
    default:
        return;
        break;
    }

    std::cout << std::endl;

    if (chkSave) {
        choice = -1;
        do {
            std::cout << "Save setting [1] yes, [2] no: ";
            choice = Utils::getSelectionAsInt(1, 2);
        } while (choice == -1);

        if (choice == 1) {
            store.storeSettings();
            // sort accounts again if sort was changed, should set a flag
            store.sortAccounts();
        } else {
            //store.get
        }
    }

    //store.reloadSettings();
}


void AccountActions::showSettings(AccountsStore &store)
{
    store.getSettings().debugSettings();
}


void AccountActions::syncAccounts()
{
    store->syncAccounts();
}


bool modifySyncSettings(AccountsStore &store) {
    std::cout << std::endl;

    std::cout << "Options:" << std::endl;
    std::cout << "1. Create Sync Account" << std::endl;
    std::cout << "2. Show Sync Account" << std::endl;
    std::cout << "3. Delete/Remove Sync Account" << std::endl;

    int choice = -1;
    do {
        std::cout << "Enter Choice: ";
        choice = Utils::getSelectionAsInt(1, 3);
    } while (choice == -1);

    switch (choice) {
    case 1:
        {
            choice = -1;
            do {
                std::cout << "\nEnter [1] to create a neww account, [2] to add an existing account: ";
                choice = Utils::getSelectionAsInt(1, 2);
            } while (choice == -1);

            bool create = (choice == 1) ? true : false;

            std::cout << "\nEnter email: ";
            std::string email;
            std::getline(std::cin, email);
            std::cout << "\nEnter password: ";
            std::string password;
            std::getline(std::cin, password);

            store.registerSync(QString::fromStdString(email), QString::fromStdString(password), create);
            break;
        }
    case 2:
    {
        OpenSSLAESEngine engine{};
        std::cout << "\nServer:   " << store.getSettings().sync.remote.server.toStdString() << std::endl;
        std::cout << "Port:     " << store.getSettings().sync.remote.port << std::endl;
        std::cout << "Protocol: " << store.getSettings().sync.remote.protocol.toStdString() << std::endl;
        std::cout << "Database: " << store.getSettings().sync.remote.db.toStdString() << std::endl;
        std::cout << "User:     " << store.getSettings().sync.remote.userName.toStdString() << std::endl;
        std::cout << "Password: " << engine.decryptPassword(store.getSettings().sync.remote.password.toStdString()) << std::endl;
        break;
    }
    case 3:
        {
            choice = -1;
            do {
                std::cout << "\nEnter [1] to delete account from server, [2] to remove it from this client: ";
                choice = Utils::getSelectionAsInt(1, 2);
            } while (choice == -1);

            bool remove = (choice == 1) ? false : true;
            store.deleteRemoveSync(store.getSettings().sync.remote.userName,
                                   store.getSettings().sync.remote.password, remove);

            break;
        }
    }


}


bool modifyGeneralSettings(Settings &settings) {
    std::cout << std::endl;

    std::cout << "Options:" << std::endl;
    std::cout << "1. Enable/Disable save key" << std::endl;
    std::cout << "2. Modify account sorting" << std::endl;
    std::cout << "3. Back" << std::endl;

    int choice = -1;
    do {
        std::cout << "Enter Choice: ";
        choice = Utils::getSelectionAsInt(1, 3);
    } while (choice == -1);

    switch (choice) {
    case 1:
        {
            choice = -1;
            do {
                std::cout << "\nEnter [1] to enable save key, [2] to disable: ";
                choice = Utils::getSelectionAsInt(1, 2);
            } while (choice == -1);

            if (choice == 1) {
                std::cout << "\nEnter key: ";
                std::string key;
                std::getline(std::cin, key);
                OpenSSLAESEngine engine{};
                std::string encrypted = engine.encryptPassword(key);
                settings.general.key = QString::fromStdString(encrypted);
                settings.general.saveKey = true;
            } else {
                settings.general.key = QString{""};
                settings.general.saveKey = false;
            }
            break;
        }
    case 2:
        {
            choice = -1;
            do {
                std::cout << "\nEnter [1] to sort account alphabetically, [2] to sort by most often accessed: ";
                choice = Utils::getSelectionAsInt(1, 2);
            } while (choice == -1);

            if (choice == 1) {
                settings.general.sortMRU = false;
            } else {
                settings.general.sortMRU = true;
            }
            break;
        }
    case 3:
        return false;
    }

    return true;
}


bool modifyDatabaseSettings(Settings & settings)
{
    std::cout << std::endl;

    std::cout << "Options:" << std::endl;
    std::cout << "1. Enable/Disable database purge" << std::endl;
    std::cout << "2. Back" << std::endl;

    int choice = -1;
    do {
        std::cout << "Enter Choice: ";
        choice = Utils::getSelectionAsInt(1, 2);
    } while (choice == -1);

    switch (choice) {
    case 1:
        choice = -1;
        do {
            std::cout << "\nEnter [1] to enable purge, [2] to disable: ";
            choice = Utils::getSelectionAsInt(1, 2);
        } while (choice == -1);

        if (choice == 1) {
            settings.database.purge = true;
            std::string selection{""};
            std::cout << "\nEnter number of days before purge after delete [0-365]: ";
            std::getline(std::cin, selection);
            int days = -1;

            try {
                days = atoi(selection.c_str());
            } catch (...) {
                std::cout << "Invalid entry, setting to 30 days" << std::endl;
                days = 30;
            }

            if (days < 0 || days > 365)
                days = 30;

            settings.database.numberOfDaysBeforePurge = days;
        } else {
            settings.database.purge = false;
        }

        break;
    case 2:
        return false;
    }

    return true;
}


bool modifyGeneratorSettings(Settings & settings)
{
    std::cout << std::endl;

    std::cout << "Options:" << std::endl;
    std::cout << "1. Override Generator options" << std::endl;
    std::cout << "2. Use default Generator options" << std::endl;
    std::cout << "3. Back" << std::endl;

    int choice = -1;
    do {
        std::cout << "Enter Choice: ";
        choice = Utils::getSelectionAsInt(1, 3);
    } while (choice == -1);

    switch (choice) {
    case 1:
    {
//        Generator g{};
        PasswordGenerator gen{settings.generator};

        bool running = true;
        do {
            choice = -1;
            std::cout << "\nOptions:" << std::endl;
            std::cout << "1. Enable/Disable lowercase characters" << std::endl;
            std::cout << "2. Enable/Disable uppercase characters" << std::endl;
            std::cout << "3. Enable/Disable digits" << std::endl;
            std::cout << "4. Enable/Disable special characters" << std::endl;
            std::cout << "5. Add character(s)" << std::endl;
            std::cout << "6. Remove character(s)" << std::endl;
            std::cout << "7. Change Length" << std::endl;
            std::cout << "8. Show current settings" << std::endl;
            std::cout << "9. Exit" << std::endl;

            do {
                std::cout << "Enter Choice: ";
                choice = Utils::getSelectionAsInt(1, 9);
            } while (choice == -1);

            switch (choice) {
                case 1:
                {
                    gen.enableLower(getBoolChoice());
                    break;
                }
                case 2:
                {
                    gen.enableUpper(getBoolChoice());
                    break;
                }
                case 3:
                {
                    gen.enableDigits(getBoolChoice());
                    break;
                }
                case 4:
                {
                    gen.enableSpecial(getBoolChoice());
                    break;
                }
                case 5:
                {
                    std::cout << "\nEnter characters to add separated by spaces: ";
                    modifyAllowedCharacters(gen, true);
                    break;
                }
                case 6:
                {
                    std::cout << "\nEnter characters to remove separated by spaces: ";
                    modifyAllowedCharacters(gen, false);
                    break;
                }
                case 7:
                {
                    std::string length{""};
                    std::cout << "\nEnter new password length: ";
                    std::getline(std::cin, length);
                    try {
                        int l = std::stoi(length);
                        if (l > 0 && l <=64)
                            gen.setPasswordLength(l);
                        else
                            std::cout << "Invalid Entry.." << std::endl;
                    } catch (...) {
                        std::cout << "Invalid Entry.." << std::endl;
                    }
                    break;
                }
                case 8:
                {
                    std::cout << "\nCurrent Generator Settings:" << std::endl;
                    std::set<char> allowedChars = gen.getAllowedCharacters();
                    std::string chars{"[ "};
                    for (auto it = allowedChars.begin(); it != allowedChars.end(); it++)
                            chars.append(std::string{*it}).append(" ");
                    chars.append("]");
                    std::cout << "Length: " << gen.getPasswordLength() << std::endl;
                    std::cout << "Allowed characters: " << chars << std::endl;
                    break;
                }
                case 9:
                    running = false;
                    break;
            }
        } while (running);

        settings.generator = gen.getGeneratorOptions();
        break;
    }
    case 2:
    {
        Generator g{};
        settings.generator = g;
        break;
    }
    case 3:
    default:
        return false;
    }

    return true;
}


std::string getPassword(AccountsStore & store)
{
    int useGenerator = -1;
    do {
        std::cout << "Enter [1] to use generator, [2] for manual: ";
        useGenerator = Utils::getSelectionAsInt(1, 2);
    } while (useGenerator == -1);

    QString pword;

    if (useGenerator == 1) {
        try {
            PasswordGenerator gen{store.getSettings().generator};
            pword = gen.generate();
        } catch (GeneratorException &ex) {
            std::cout << "Error generating password: " << ex.what() << std::endl;
            throw  ex;
        }
    } else {
        std::cout << "Enter new password: ";
        std::string pword_str;
        std::getline(std::cin, pword_str);
        pword = QString::fromStdString(pword_str);
    }

std::cout << "password: " << pword.toStdString() << std::endl;
    try {
        std::string encrypted = store.getEncryptionEngine()->encryptPassword(pword.toStdString());
        std::cout << "Encrypted password: " << encrypted << std::endl;
        return encrypted;
    } catch (EncryptionException &ex) {
        std::cout << "Error encrypting password: " << ex.what() << std::endl;
        throw ex;
    }
}


bool getBoolChoice()
{
    int choice = -1;
    do {
        std::cout << "\n1. Enable" << std::endl;
        std::cout << "2. Disable" << std::endl;
        std::cout << "Enter Choice: ";
        choice = Utils::getSelectionAsInt(1, 2);
    } while (choice == -1);

    if (choice == 1)
        return true;
    else
        return false;
}


void modifyAllowedCharacters(PasswordGenerator & gen, bool add)
{
    std::string chars{""};
    std::getline(std::cin, chars);

    for (auto it = chars.cbegin(); it != chars.cend(); it++) {
        if (*it == ' ')
            continue;

        if (add)
            gen.addChar(*it);
        else
            gen.removeChar(*it);
    }

}
