#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>
#include <QTreeWidget>
namespace Ui {
class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = 0);
    ~Dialog();

private slots:
    void on_treeWidget_itemDoubleClicked(QTreeWidgetItem *item);


signals:
     void Line1Changed(const QString&);

private:
    Ui::Dialog *ui;
    void addTreeRoot(QString name, QString description);
};




#endif // DIALOG_H
