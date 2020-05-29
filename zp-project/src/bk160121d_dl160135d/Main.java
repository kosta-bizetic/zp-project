package bk160121d_dl160135d;

import java.awt.CardLayout;
import java.awt.FileDialog;
import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuBar;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.border.TitledBorder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;

import bk160121d_dl160135d.KeyManagement.RSA_KEYSIZE;

public class Main extends JFrame {
    private static final long serialVersionUID = 1L;

    private static final String HomeCard = "home",
                                CreateCard = "create";

    private KeyManagement keyManagement = KeyManagement.getInstance();
    private JTable secretKeyTable = null,
                   publicKeyTable = null;

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

    private void addSecretKeyTable(JPanel panel, java.util.List<java.util.List<String>> keyInfoList) {
        secretKeyTable = new JTable(new KeysTableModel(keyInfoList));
        JScrollPane sp = new JScrollPane(secretKeyTable);
        sp.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(),
                     "My Keys",
                     TitledBorder.CENTER,
                     TitledBorder.TOP));
        panel.add(sp);
    }

    private void addPublicKeyTable(JPanel panel, java.util.List<java.util.List<String>> keyInfoList) {
        publicKeyTable = new JTable(new KeysTableModel(keyInfoList));
        JScrollPane sp = new JScrollPane(publicKeyTable);
        sp.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(),
                     "Other keys",
                     TitledBorder.CENTER,
                     TitledBorder.TOP));
        panel.add(sp);
    }

    private void addHomeCard(JPanel cards) {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(2, 1));
        addSecretKeyTable(panel, keyManagement.getSecretKeyList());
        addPublicKeyTable(panel, keyManagement.getPublicKeyList());
        cards.add(panel, HomeCard);
    }

    private void addCreateCard(JPanel cards) {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(0, 1));

        JTextField name = new JTextField(),
                   email = new JTextField();

        JPasswordField passphrase = new JPasswordField();

        ButtonGroup size = new ButtonGroup();
        JRadioButton small = new JRadioButton("Small"),
                     medium = new JRadioButton("Medium"),
                     large = new JRadioButton("Large");
        size.add(small);
        size.add(medium);
        size.add(large);
        JPanel radioButtons = new JPanel(new GridLayout(0, 3));
        radioButtons.add(small);
        small.setSelected(true);
        radioButtons.add(medium);
        radioButtons.add(large);

        JButton createButton = new JButton("Create");
        createButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String identity = name.getText() + '<' + email.getText() + '>';
                KeyManagement.RSA_KEYSIZE keySize = RSA_KEYSIZE.SMALL;
                if (medium.isSelected()) {
                    keySize = RSA_KEYSIZE.MEDIUM;
                } else if (large.isSelected()) {
                    keySize = RSA_KEYSIZE.LARGE;
                }

                try {
                    keyManagement.generateRSAKeyPair(keySize, identity, passphrase.getPassword());
                } catch (NoSuchAlgorithmException | NoSuchProviderException | PGPException | IOException e1) {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }

                secretKeyTable.setModel(new KeysTableModel(keyManagement.getSecretKeyList()));

                CardLayout cl = (CardLayout) (cards.getLayout());
                cl.show(cards, HomeCard);
            }
        });

        panel.add(new JLabel("Name:"));
        panel.add(name);
        panel.add(new JLabel("Email:"));
        panel.add(email);
        panel.add(new JLabel("Size:"));
        panel.add(radioButtons);
        panel.add(new JLabel("Passphrase:"));
        panel.add(passphrase);
        panel.add(createButton);

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
                keyManagement.close();
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
        Security.addProvider(new BouncyCastleProvider());
        new Main();
    }

}
