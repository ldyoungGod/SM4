TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    Encrypt.cpp \
    XSM4.cpp

HEADERS += \
    Encrypt.h \
    XSM4.h
