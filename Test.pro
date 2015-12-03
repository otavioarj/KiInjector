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
         inject.cpp



HEADERS  +=  inject.h\
#             mythread.h \
            mainwindow.h

OBJECTS += asm.o

FORMS    += mainwindow.ui

DEFINES = QT_STATIC_BUILD STATIC QT_NO_DEBUG QT_WIDGETS_LIB QT_GUI_LIB QT_CORE_LIB QT_NEEDS_QMAIN
QTPLUGIN = qico
RESOURCES = a.qrc
QMAKE_CFLAGS   = -Ofast -march=core2
QMAKE_CXXFLAGS =  -Ofast -momit-leaf-frame-pointer  -march=core2
static {
QMAKE_LIBS =   -lmingw32 -LC:/Qt/Static/5.5.0/lib -lqtmain -lQt5Widgets -LC:/Qt/Static/5.5.0/plugins/platforms -lqwindows -lwinspool -lshlwapi -lQt5PlatformSupport -lqtfreetype -LC:/Qt/Static/5.5.0/plugins/imageformats -lqdds -lqicns -lqico -lqjp2 -lqmng -lqtga -lqtiff -lqwbmp -lqwebp -lQt5Gui -lcomdlg32 -loleaut32 -limm32 -lwinmm -lglu32 -lopengl32 -lgdi32 -lqtharfbuzzng -lQt5Core -lole32 -luuid -lws2_32 -ladvapi32 -lshell32 -luser32 -lkernel32 -lmpr -lqtpcre

# -lmingw32 -LC:/Qt/Static/5.5.0/lib -lqtmain -lQt5Widgets -LC:/Qt/Static/5.5.0/plugins/platforms -lqwindows -lshlwapi -lQt5PlatformSupport -lqico -lqtfreetype -LC:/Qt/Static/5.5.0/plugins/imageformats -lQt5Gui -lQt5Core -luser32 -lkernel32 -lmpr -lqtpcre
QMAKE_LFLAGS  =  -static -static-libgcc -Wl,-s -s

 # everything below takes effect with CONFIG ''= static
 message("~~~ static build ~~~") # this is for information, that the static build is done
 }
QMAKE_LIBS +=  -lpsapi -lShlwapi
# -lOleAut32
