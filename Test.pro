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


#CONFIG += DEV


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
QMAKE_CXXFLAGS =  -Ofast -fomit-frame-pointer  -march=native -Wno-shift-count-overflow -Wno-unused-local-typedefs   -Wno-missing-field-initializers -Wno-format -fpermissive
#  -LC:/Qt/Static2/5.7/plugins/platforms -LC:/Qt/Static2/5.7/plugins/imageformats  -lqico -lQt5Core

QMAKE_LIBS =   -Wl,-Bstatic -lstdc++ -lpthread -Wl,-Bdynamic  -lgdi32 -luser32 -lkernel32

#QMAKE_LIBS =   -Wl,-Bstatic -lstdc++ -lpthread -lqtmain  -LC:/Qt/Static2/5.7/plugins/platforms -lqwindows  -LC:/Qt/Static2/5.7/plugins/imageformats -lqico -lQt5Core -Wl,-Bdynamic  -lgdi32 -luser32 -lkernel32

#QMAKE_LIBS =  -lmingw32 -lqtmain -lQt5Widgets -LC:/Qt/Static2/5.7/plugins/platforms -lqwindows -lwinspool -lQt5PlatformSupport -lqtfreetype -LC:/Qt/Static2/5.7/plugins/imageformats -lqdds -lqicns -lqico -lqtga -lqtiff -lqwbmp -lqwebp -lQt5Gui -lcomdlg32 -loleaut32 -limm32 -lwinmm -lglu32 -lopengl32 -lgdi32 -lqtharfbuzzng -lQt5Core -lole32 -luuid -lws2_32 -ladvapi32 -lshell32 -luser32 -lkernel32 -lmpr -lqtpcre


QMAKE_LFLAGS  = -static-libgcc  -static-libstdc++ -s # -Wl,-s


QMAKE_LIBS += -Wl,-Bdynamic -lpsapi -lShlwapi  -lOleAut32

DISTFILES += \
    myrc.rc
