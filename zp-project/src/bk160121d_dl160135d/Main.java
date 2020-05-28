package bk160121d_dl160135d;

import java.awt.FileDialog;
import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.Menu;
import java.awt.MenuBar;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.BorderFactory;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.border.TitledBorder;

public class Main extends Frame {
    private static final long serialVersionUID = 1L;

    private KeyManagement keyManagement = KeyManagement.getInstance();

    private String selectFile() {
        FileDialog fd = new FileDialog(new Frame());
        fd.setVisible(true);
        if(fd.getFiles().length > 0){
            return fd.getFiles()[0].getAbsolutePath();
        }
        return null;
    }

    private void createKeysHandler() {
        System.out.println("create");
    }

    private void enryptHandler() {
        System.out.println(selectFile());
    }

    private void decryptHandler() {
        System.out.println(selectFile());
    }

    private void verifyHandler() {
        System.out.println(selectFile());
    }

    private void addMenu() {
        MenuBar menuBar = new MenuBar();
        Menu menu = new Menu("Actions");
        menu.add("Create key pair");
        menu.add("Encrypt/Sign");
        menu.add("Decrypt");
        menu.add("Verify");
        menu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String action = e.getActionCommand();
                switch (action) {
                case "Create key pair":
                    createKeysHandler();
                    break;
                case "Encrypt/Sign":
                    enryptHandler();
                    break;
                case "Decrypt":
                    decryptHandler();
                    break;
                case "Verify":
                    verifyHandler();
                    break;
                }
            }
        });
        menuBar.add(menu);
        setMenuBar(menuBar);
    }

    private void addKeysTable(String title, java.util.List<java.util.List<String>> keyInfoList) {
        JTable jt = new JTable(new KeysTableModel(keyInfoList));
        JScrollPane sp = new JScrollPane(jt);
        sp.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(),
                     title,
                     TitledBorder.CENTER,
                     TitledBorder.TOP));
        add(sp);
    }

    private void addComponents() {
        addMenu();
        setLayout(new GridLayout(2, 1));
        addKeysTable("My Keys", keyManagement.getSecretKeyList());
        addKeysTable("Other Keys", keyManagement.getPublicKeyList());
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent we) {
                dispose();
            }});
    }

    public Main() {
        super("OpenPGP");
        setBounds(300, 300, 600, 300);
        setResizable(false);
        addComponents();
        setVisible(true);
    }

    public static void main(String[] args) {
        new Main();
    }

}
