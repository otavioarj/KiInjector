#-------------------------------------------------
#
# Project created by QtCreator 2015-10-02T04:01:10
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Test
TEMPLATE = app


SOURCES += main.cpp\
#         mythread.cpp \
         mainwindow.cpp \
         inject.cpp \
         loadll.cpp \
       loadwapper.cpp \
    pebhider.cpp \
    mmap.cpp \
    getmod.cpp


HEADERS  +=  inject.h\
#             mythread.h \
            mainwindow.h \
    antis.h

OBJECTS +=  ..\Pload.o \
            #Aasm.o \

FORMS    += mainwindow.ui

DEFINES += QT_NO_DEBUG QT_NO_CAST_TO_ASCII
DEFINES -= QT_LARGEFILE_SUPPORT UNICODE


CONFIG += windows #DEV


DEV{
DEFINES+= DEV
message("~~~ DEV ~~~")
}

x64 {
message("~~~ Win64 ~~~")
OBJECTS -=  ..\Pload.o
OBJECTS +=  ..\Pload64.o
DEFINES+= _WIN64
}
#QTPLUGIN = qico
RC_FILE = myrc.rc
#RESOURCES = a.qrc

#QMAKE_CFLAGS   = -Ofast -march=native  -fomit-frame-pointer    -Wno-missing-field-initializers -fpermissive
QMAKE_CXXFLAGS =  -O2 -fomit-frame-pointer  -march=sandybridge -Wno-shift-count-overflow -Wno-unused-local-typedefs -Wno-attributes -Wno-int-in-bool-context -Wno-missing-field-initializers -Wno-format -fpermissive

QMAKE_LIBS =  -Wl,-Bdynamic -lgdi32 -luser32 -lkernel32 -lpsapi -lShlwapi  -lOleAut32
QMAKE_LFLAGS = -static-libstdc++ -static-libgcc -lpthread
#QMAKE_LIBS =   -Wl,-Bstatic -lstdc++ -lpthread -lqtmain  -LC:/Qt/Static2/5.7/plugins/platforms -lqwindows  -LC:/Qt/Static2/5.7/plugins/imageformats -lqico -lQt5Core -Wl,-Bdynamic  -lgdi32 -luser32 -lkernel32


DISTFILES += \
    myrc.rc \
