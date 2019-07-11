#include <QCoreApplication>
#include <QSslConfiguration>

#include "accountsstore.h"
#include "accountactions.h"
#include "utils.h"
#include "sync.h"


#include <iostream>
#include <string>
#include <QStandardItem>

#include <csignal>


#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
//#include <QVariantMap>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkRequest>
#include <QNetworkReply>


void test_save(AccountsStore&);
int run(AccountsStore &, AccountActions &);
void printMenu();
std::string getKey();

AccountsStore *store = new AccountsStore{};
AccountActions *actions = new AccountActions{store};

void signal_handler(int signal)
{
  std::cout << "Signal received: " << signal << std::endl;
  std::cout << "Saving store..." << std::endl;
  store->storeAccounts();
  std::cout << "Finished saving store..." << std::endl;
  exit(signal);
}


int main(int argc, char *argv[])
{
    std::signal(SIGINT, signal_handler);
    std::signal(SIGKILL, signal_handler);
    std::signal(SIGHUP, signal_handler);
    std::signal(SIGABRT, signal_handler);
    std::signal(SIGSTOP, signal_handler);
    std::signal(SIGQUIT, signal_handler);

    QCoreApplication a(argc, argv);
//    return a.exec();

//    std::string key = getKey();
//    std::cout << "key: " << key << std::endl;
//    AccountsStore store{"TestKey"};

//    AccountsStore store{getKey()};
//    AccountsStore store{};
    Settings settings = store->getSettings();

    std::string key{};

    if (settings.general.saveKey) {
        std::string encrypted = settings.general.key.toStdString();
//        OpenSSLAESEngine engine{};
        key = store->getEncryptionEngine()->decryptPassword(encrypted);
    } else {
        key = getKey();
    }

//    AccountsStore store2{key};

//    run(store2);
    store->setEncryptionKey(key);


    run(*store, *actions);


//    store.setStoreLocation("/opt/qt_passvault_store");

//    test_save(store);
//    store.storeAccounts();
//    store.storeSettings();
}


int run(AccountsStore &store, AccountActions &actions)
{
    bool running = true;

    do {
        printMenu();
        int val = Utils::getSelectionAsInt(1, 9);
        /*
        std::string selection;
        std::getline(std::cin, selection);
        int val;

        try {
            val = std::stoi(selection);
        } catch (...) {
            std::cout << "Inavlid Selection" << std::endl;
            continue;
        }
        */

        switch (val) {
        case 1:
            actions.listAccounts(store);
            break;
        case 2:
            actions.copyPassword(store);
            break;
        case 3:
            actions.addAccount(store);
            break;
        case 4:
            actions.deleteAccount(store);
            break;
        case 5:
            actions.editAccount(store);
            break;
        case 6:
            actions.showSettings(store);
            break;
        case 7:
            actions.editSettings(store);
            break;
        case 8:
            actions.syncAccounts();
            break;
        case 9:
            running = false;
            store.storeAccounts();
            break;
        default:

            break;
        }


    } while (running);

    return 1;

}


void printMenu()
{
    std::cout << std::endl;
    std::cout << "Passvault Main Menu:" << std::endl;
    std::cout << "1. Show Accounts" << std::endl;
    std::cout << "2. Copy Account Password" << std::endl;
    std::cout << "3. Add Account" << std::endl;
    std::cout << "4. Delete Account" << std::endl;
    std::cout << "5. Edit Account" << std::endl;
    std::cout << "6. Show Settings" << std::endl;
    std::cout << "7. Edit Settings" << std::endl;
    std::cout << "8. Sync Accounts" << std::endl;
    std::cout << "9. Exit" << std::endl;
    std::cout << std::endl;
    std::cout << "Enter Selection: " << std::endl;

}


std::string getKey()
{
    std::cout << std::endl;
    std::cout << "Enter Key: ";

    std::string selection;
    std::getline(std::cin, selection);
    return selection;
}


void test_save(AccountsStore &store) {
    Account *a1 = new Account{"account1", "user1", "pass1", "old_pass", "www.yahoo.com"};
    Account *a2 = new Account{"account2", "user2", "pass2", "old_pass", "www.yahoo.com"};
    Account *a3 = new Account{"account3", "user3", "pass3", "old_pass", "www.yahoo.com"};
    store.addAccount(a1);
    store.addAccount(a2);
    store.addAccount(a3);
}
