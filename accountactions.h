#ifndef ACCOUNTACTIONS_H
#define ACCOUNTACTIONS_H

#include "accountsstore.h"
#include "account.h"


class AccountActions : public QObject
{
    Q_OBJECT
public:
    AccountActions(AccountsStore *);
//    AccountActions() {}

    void addAccount(AccountsStore &);
    bool deleteAccount(AccountsStore &);
    void copyPassword(AccountsStore &);
    void editAccount(AccountsStore &);
    void listAccounts(AccountsStore &);
    void editSettings(AccountsStore &);
    void showSettings(AccountsStore &);
    void syncAccounts();

private:
    AccountsStore *store;
};



#endif // ACCOUNTACTIONS_H
