/*
 * This file is part of LuHPoS project. This software may be used and distributed
 * according to the terms of the GNU General Public License version 3, incorporated herein by reference
 * at repository: https://github.com/otavioarj/KiInjector
 =]
*/

#include "mainwindow.h"
#include <QApplication>



int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();

}
