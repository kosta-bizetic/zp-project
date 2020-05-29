package bk160121d_dl160135d;

import java.awt.CardLayout;
import java.awt.FileDialog;
import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuBar;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.border.TitledBorder;

public class Main extends JFrame {
    private static final long serialVersionUID = 1L;

    private static final String HomeCard = "home",
                                CreateCard = "create";

    private KeyManagement keyManagement = KeyManagement.getInstance();

    private String selectFile() {
        FileDialog fd = new FileDialog(new Frame());
        fd.setVisible(true);
        if(fd.getFiles().length > 0){
            return fd.getFiles()[0].getAbsolutePath();
        }
        return null;
    }

    private void turnButtonIntoMenuItem(JButton button) {
        button.setOpaque(true);
        button.setContentAreaFilled(false);
//        button.setBorderPainted(false);
        button.setFocusable(false);
    }

    private void addMenu(JPanel cards) {
        JMenuBar menuBar = new JMenuBar();
        JButton create = new JButton("Create key pair"),
                encrypt = new JButton("Encrypt/Sign"),
                decrypt = new JButton("Decrypt"),
                verify = new JButton("Verify");

        turnButtonIntoMenuItem(create);
        turnButtonIntoMenuItem(encrypt);
        turnButtonIntoMenuItem(decrypt);
        turnButtonIntoMenuItem(verify);

        create.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CardLayout cl = (CardLayout) (cards.getLayout());
                cl.show(cards, CreateCard);
            }
        });

        encrypt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO
            }
        });

        decrypt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO
            }
        });

        verify.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO
            }
        });

        menuBar.add(create);
        menuBar.add(encrypt);
        menuBar.add(decrypt);
        menuBar.add(verify);
        setJMenuBar(menuBar);
    }

    private void addKeysTable(JPanel panel, String title, java.util.List<java.util.List<String>> keyInfoList) {
        JTable jt = new JTable(new KeysTableModel(keyInfoList));
        JScrollPane sp = new JScrollPane(jt);
        sp.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(),
                     title,
                     TitledBorder.CENTER,
                     TitledBorder.TOP));
        panel.add(sp);
    }

    private void addHomeCard(JPanel cards) {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(2, 1));
        addKeysTable(panel, "My Keys", keyManagement.getSecretKeyList());
        addKeysTable(panel, "Other Keys", keyManagement.getPublicKeyList());
        cards.add(panel, HomeCard);
    }

    private void addCreateCard(JPanel cards) {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(2, 1));

        // TODO

        panel.add(new JLabel("test"));
        cards.add(panel, CreateCard);
    }

    private void addComponents() {
        JPanel cards = new JPanel(new CardLayout());
        addHomeCard(cards);
        addCreateCard(cards);
        add(cards);
        addMenu(cards);
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
