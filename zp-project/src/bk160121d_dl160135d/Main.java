package bk160121d_dl160135d;

import java.awt.Frame;
import java.awt.Menu;
import java.awt.MenuBar;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

public class Main extends Frame {
    private static final long serialVersionUID = 1L;

    private void createKeysHandler() {
        System.out.println("create");
    }

    private void enryptHandler() {
        System.out.println("encrypt");
    }

    private void decryptHandler() {
        System.out.println("decrypt");
    }

    private void verifyHandler() {
        System.out.println("verify");
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

    private void addComponents() {
        addMenu();
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

//        public static void main(
//            String[] args)
//            throws Exception
//        {
//            Security.addProvider(new BouncyCastleProvider());
//
//            KeyManagement keyManagement = KeyManagement.getInstance();
//
//            List<PGPPublicKey> pubKeys = new LinkedList<PGPPublicKey>();
//
//            pubKeys.add(keyManagement.getPublicKey(688238868389858045l));
//            pubKeys.add(keyManagement.getPublicKey(6921129671440841737l));
//
//            FileOutputStream out = new FileOutputStream("message.txt.sig");
//
//            SignatureManagment.signFile("message.txt", 688238868389858045l, out, "stagod".toCharArray());
//
//            CryptionManagement.encryptFile("message.txt.sig.gpg", "message.txt.sig", pubKeys , false, true, PGPEncryptedData.IDEA);
//
//            CryptionManagement.decryptFile("message.txt.sig.gpg", keyManagement.getSecretKeyRingCollection(), "stagod".toCharArray());
//
//            SignatureManagment.verifyFile("message.txt.sig");
//
//            keyManagement.printSecretKeyRingCollection();
//            keyManagement.close();
//        }
}
