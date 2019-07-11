QT += network gui

CONFIG += c++11 console gui core network
CONFIG -= app_bundle

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        accountactions.cpp \
        main.cpp

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../../passvault_core/build-passvault_core-Desktop_Qt_5_12_3_clang_64bit-Debug/release/ -lpassvault_core
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../passvault_core/build-passvault_core-Desktop_Qt_5_12_3_clang_64bit-Debug/debug/ -lpassvault_core
else:unix: LIBS += -L$$PWD/../../passvault_core/build-passvault_core-Desktop_Qt_5_12_3_clang_64bit-Debug/ -lpassvault_core

INCLUDEPATH += $$PWD/../../passvault_core/passvault_core
DEPENDPATH += $$PWD/../../passvault_core/passvault_core

win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../../passvault_core/build-passvault_core-Desktop_Qt_5_12_3_clang_64bit-Debug/release/libpassvault_core.a
else:win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../../passvault_core/build-passvault_core-Desktop_Qt_5_12_3_clang_64bit-Debug/debug/libpassvault_core.a
else:win32:!win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../../passvault_core/build-passvault_core-Desktop_Qt_5_12_3_clang_64bit-Debug/release/passvault_core.lib
else:win32:!win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../../passvault_core/build-passvault_core-Desktop_Qt_5_12_3_clang_64bit-Debug/debug/passvault_core.lib
else:unix: PRE_TARGETDEPS += $$PWD/../../passvault_core/build-passvault_core-Desktop_Qt_5_12_3_clang_64bit-Debug/libpassvault_core.a

HEADERS += \
    accountactions.h

macx: LIBS += -L$$PWD/../../../../../../opt/openssl/openssl-1.1.1c_install/lib/ -lcrypto

INCLUDEPATH += $$PWD/../../../../../../opt/openssl/openssl-1.1.1c_install/include
DEPENDPATH += $$PWD/../../../../../../opt/openssl/openssl-1.1.1c_install/include

macx: PRE_TARGETDEPS += $$PWD/../../../../../../opt/openssl/openssl-1.1.1c_install/lib/libcrypto.a



INCLUDEPATH += $$PWD/''
DEPENDPATH += $$PWD/''
