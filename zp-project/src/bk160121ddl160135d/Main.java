package bk160121ddl160135d;

import java.awt.CardLayout;
import java.awt.Color;
import java.awt.FileDialog;
import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.ArrayList;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
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
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;

import bk160121ddl160135d.KeyManagement.RSA_KEYSIZE;

public class Main extends JFrame {
    private static final long serialVersionUID = 1L;

    private static final String HomeCard = "home",
                                CreateCard = "create",
                                ImportCard = "import",
                                EncryptCard = "encrypt",
                                DecryptCard = "decrypt",
                                VerifyCard = "verify";

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
        JButton home = new JButton("Home"),
                create = new JButton("Create key pair"),
                importButton = new JButton("Import key"),
                encrypt = new JButton("Encrypt/Sign"),
                decrypt = new JButton("Decrypt"),
                verify = new JButton("Verify");

        turnButtonIntoMenuItem(home);
        turnButtonIntoMenuItem(create);
        turnButtonIntoMenuItem(importButton);
        turnButtonIntoMenuItem(encrypt);
        turnButtonIntoMenuItem(decrypt);
        turnButtonIntoMenuItem(verify);

        home.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CardLayout cl = (CardLayout) (cards.getLayout());
                cl.show(cards, HomeCard);
            }
        });

        importButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CardLayout cl = (CardLayout) (cards.getLayout());
                cl.show(cards, ImportCard);
            }
        });

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
                CardLayout cl = (CardLayout) (cards.getLayout());
                cl.show(cards, EncryptCard);
            }
        });

        decrypt.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CardLayout cl = (CardLayout) (cards.getLayout());
                cl.show(cards, DecryptCard);
            }
        });

        verify.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CardLayout cl = (CardLayout) (cards.getLayout());
                cl.show(cards, VerifyCard);
            }
        });

        menuBar.add(home);
        menuBar.add(create);
        menuBar.add(importButton);
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
        JPanel panel = new JPanel(new GridLayout(4, 1));

        addSecretKeyTable(panel, keyManagement.getSecretKeyList());

        JPanel myKeysButtonPanel = new JPanel(new GridLayout(1, 3));

        JButton exportMySecretButton = new JButton("Export secret key");
        exportMySecretButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String email = (String) secretKeyTable.getValueAt(secretKeyTable.getSelectedRow(), 1);
                long keyID =
                        Long.parseLong(((String) secretKeyTable.getValueAt(secretKeyTable.getSelectedRow(), 2)));

                keyManagement.exportSecretKey(keyID, email + "-secret.asc");
            }
        });
        myKeysButtonPanel.add(exportMySecretButton);

        JButton exportMyPublicButton = new JButton("Export public key");
        exportMyPublicButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String email = (String) secretKeyTable.getValueAt(secretKeyTable.getSelectedRow(), 1);
                long keyID =
                        Long.parseLong(((String) secretKeyTable.getValueAt(secretKeyTable.getSelectedRow(), 2)));

                keyManagement.exportPublicKey(keyID, email + "-public.asc");
            }
        });
        myKeysButtonPanel.add(exportMyPublicButton);

        JButton deleteMyKeyButton = new JButton("Delete key");
        deleteMyKeyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                long keyID =
                        Long.parseLong(((String) secretKeyTable.getValueAt(secretKeyTable.getSelectedRow(), 2)));

                keyManagement.deleteSecretKey(keyID);

                secretKeyTable.setModel(new KeysTableModel(keyManagement.getSecretKeyList()));
            }
        });
        myKeysButtonPanel.add(deleteMyKeyButton);

        panel.add(myKeysButtonPanel);

        addPublicKeyTable(panel, keyManagement.getPublicKeyList());

        JPanel otherKeysButtonPanel = new JPanel(new GridLayout(1, 2));

        JButton exportPublicButton = new JButton("Export public key");
        exportPublicButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String email = (String) publicKeyTable.getValueAt(publicKeyTable.getSelectedRow(), 1);
                long keyID =
                        Long.parseLong(((String) publicKeyTable.getValueAt(publicKeyTable.getSelectedRow(), 2)));

                keyManagement.exportPublicKey(keyID, email + "-public.asc");
            }
        });
        otherKeysButtonPanel.add(exportPublicButton);

        JButton deleteOtherKeyButton = new JButton("Delete key");
        deleteOtherKeyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                long keyID =
                        Long.parseLong(((String) publicKeyTable.getValueAt(publicKeyTable.getSelectedRow(), 2)));

                keyManagement.deletePublicKey(keyID);

                publicKeyTable.setModel(new KeysTableModel(keyManagement.getPublicKeyList()));
            }
        });
        otherKeysButtonPanel.add(deleteOtherKeyButton);

        panel.add(otherKeysButtonPanel);

        cards.add(panel, HomeCard);
    }

    private void addCreateCard(JPanel cards) {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(0, 1));

        JTextField name = new JTextField(),
                   email = new JTextField();

        JPasswordField passphrase = new JPasswordField();

        ButtonGroup size = new ButtonGroup();
        JRadioButton small = new JRadioButton("Small (1024b)"),
                     medium = new JRadioButton("Medium (2048b)"),
                     large = new JRadioButton("Large (4096b)");
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

    private void addImportCard(JPanel cards) {
        JPanel panel = new JPanel(new GridLayout(0, 1));

        JPanel publicFilepickerPanel = new JPanel(new GridLayout(1, 0));
        JLabel publicFilePathLabel = new JLabel("No file selected.");
        JButton publicFilepickerButton = new JButton("Choose file");
        publicFilepickerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                publicFilePathLabel.setText(selectFile());
            }
        });
        publicFilepickerPanel.add(publicFilepickerButton);
        publicFilepickerPanel.add(publicFilePathLabel);

        JButton publicImportButton = new JButton("Import public key");
        publicImportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                keyManagement.importPublicKey(publicFilePathLabel.getText());

                publicKeyTable.setModel(new KeysTableModel(keyManagement.getPublicKeyList()));

                CardLayout cl = (CardLayout) (cards.getLayout());
                cl.show(cards, HomeCard);
            }
        });

        JPanel secretFilepickerPanel = new JPanel(new GridLayout(1, 0));
        JLabel secretFilePathLabel = new JLabel("No file selected.");
        JButton secretFilepickerButton = new JButton("Choose file");
        secretFilepickerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                secretFilePathLabel.setText(selectFile());
            }
        });
        secretFilepickerPanel.add(secretFilepickerButton);
        secretFilepickerPanel.add(secretFilePathLabel);

        JButton secretImportButton = new JButton("Import secret key");
        secretImportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                keyManagement.importSecretKey(secretFilePathLabel.getText());

                secretKeyTable.setModel(new KeysTableModel(keyManagement.getSecretKeyList()));

                CardLayout cl = (CardLayout) (cards.getLayout());
                cl.show(cards, HomeCard);
            }
        });

        panel.add(secretFilepickerPanel);
        panel.add(secretImportButton);
        panel.add(publicFilepickerPanel);
        panel.add(publicImportButton);

        cards.add(panel, ImportCard);
    }

    private void addEncryptCard(JPanel cards) {
        JPanel panel = new JPanel(new GridLayout(0, 1));

        JCheckBox encryptFileCB = new JCheckBox("Encrypt file"),
                  signFileCB = new JCheckBox("Sign file"),
                  compressionCB = new JCheckBox("Compress file"),
                  radixCB = new JCheckBox("Radix-64");

        JTable signatureKeyList = new JTable(new KeysTableModel(keyManagement.getSecretKeyList()));
        JScrollPane signatureKeyScrollPane = new JScrollPane(signatureKeyList);
        signatureKeyScrollPane.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(),
                     "Select signature key",
                     TitledBorder.CENTER,
                     TitledBorder.TOP));

        JLabel passphraseLabel = new JLabel("Passphrase:");
        JPasswordField passphrase = new JPasswordField();

        signatureKeyScrollPane.setVisible(false);
        passphraseLabel.setVisible(false);
        passphrase.setVisible(false);
        signFileCB.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                signatureKeyScrollPane.setVisible(!signatureKeyScrollPane.isVisible());
                passphraseLabel.setVisible(!passphraseLabel.isVisible());
                passphrase.setVisible(!passphrase.isVisible());
            }
        });

        JPanel algoChoicePanel = new JPanel(new GridLayout(1, 0));
        ButtonGroup encAlgorithms = new ButtonGroup();
        JRadioButton idea = new JRadioButton("IDEA"),
                     tdes = new JRadioButton("3DES-EDE");
        encAlgorithms.add(tdes);
        encAlgorithms.add(idea);
        algoChoicePanel.add(tdes);
        tdes.setSelected(true);
        algoChoicePanel.add(idea);

        java.util.List<java.util.List<String>> allKeys = keyManagement.getSecretKeyList();
        allKeys.addAll(keyManagement.getPublicKeyList());
        JTable encryptionKeyList = new JTable(new KeysTableModel(allKeys));
        JScrollPane encryptionKeyScrollPane = new JScrollPane(encryptionKeyList);
        encryptionKeyScrollPane.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(),
                     "Encrypt for:",
                     TitledBorder.CENTER,
                     TitledBorder.TOP));
        encryptionKeyScrollPane.setVisible(false);

        algoChoicePanel.setVisible(false);
        compressionCB.setVisible(false);
        radixCB.setVisible(false);
        encryptFileCB.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                algoChoicePanel.setVisible(!algoChoicePanel.isVisible());
                encryptionKeyScrollPane.setVisible(!encryptionKeyScrollPane.isVisible());
                compressionCB.setVisible(!compressionCB.isVisible());
                radixCB.setVisible(!radixCB.isVisible());
            }
        });

        JPanel filepickerPanel = new JPanel(new GridLayout(1, 0));
        JLabel filePathLabel = new JLabel("No file selected.");
        JButton filepickerButton = new JButton("Choose file");
        filepickerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                filePathLabel.setText(selectFile());
            }
        });
        filepickerPanel.add(filepickerButton);
        filepickerPanel.add(filePathLabel);

        JButton submitButton = new JButton("Submit");
        submitButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String inputFilePath = filePathLabel.getText();

                if (signFileCB.isSelected()) {
                    long signKeyID =
                            Long.parseLong(((String) signatureKeyList.getValueAt(signatureKeyList.getSelectedRow(), 2)));
                    try (FileOutputStream out =  new FileOutputStream(inputFilePath + ".sig")) {
                        SignatureManagment.signFile(inputFilePath, signKeyID, out, passphrase.getPassword());
                    } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | IOException
                            | PGPException e1) {
                        // TODO Hendlovati pogresnu sifru
                        e1.printStackTrace();
                    }
                }

                if (encryptFileCB.isSelected()) {
                    java.util.List<PGPPublicKey> encryptionKeyList = new ArrayList<>();
                    long encryptKeyID =
                            Long.parseLong(((String) signatureKeyList.getValueAt(signatureKeyList.getSelectedRow(), 2)));
                    encryptionKeyList.add(keyManagement.getPublicKey(encryptKeyID));

                    int encAlgo = PGPEncryptedData.TRIPLE_DES;
                    if (idea.isSelected()) encAlgo = PGPEncryptedData.IDEA;

                    if (signFileCB.isSelected()) inputFilePath += ".sig";

                    try {
                        CryptionManagement.encryptFile(
                                inputFilePath + ".gpg",
                                inputFilePath,
                                encryptionKeyList,
                                radixCB.isSelected(),
                                compressionCB.isSelected(),
                                encAlgo);
                    } catch (NoSuchProviderException | IOException | PGPException e1) {
                        // TODO Auto-generated catch block
                        e1.printStackTrace();
                    }
                }

                CardLayout cl = (CardLayout) (cards.getLayout());
                cl.show(cards, HomeCard);
            }
        });

        panel.add(signFileCB);
        panel.add(signatureKeyScrollPane);
        panel.add(passphraseLabel);
        panel.add(passphrase);
        panel.add(encryptFileCB);
        panel.add(algoChoicePanel);
        panel.add(encryptionKeyScrollPane);
        panel.add(compressionCB);
        panel.add(radixCB);
        panel.add(filepickerPanel);
        panel.add(submitButton);

        cards.add(panel, EncryptCard);
    }

    private void addDecryptCard(JPanel cards) {
        JPanel panel = new JPanel(new GridLayout(0, 1));

        JLabel passphraseLabel = new JLabel("Passphrase:");
        JPasswordField passphrase = new JPasswordField();

        JPanel filepickerPanel = new JPanel(new GridLayout(1, 0));
        JLabel filePathLabel = new JLabel("No file selected.");
        JButton filepickerButton = new JButton("Choose file");
        filepickerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                filePathLabel.setText(selectFile());
            }
        });
        filepickerPanel.add(filepickerButton);
        filepickerPanel.add(filePathLabel);

        JButton decryptButton = new JButton("Decrypt");
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    CryptionManagement.decryptFile(
                            filePathLabel.getText(),
                            keyManagement.getSecretKeyRingCollection(),
                            passphrase.getPassword());
                } catch (NoSuchProviderException | IOException e1) {
                    // TODO Hendlovati pogresnu sifru
                    e1.printStackTrace();
                }

                CardLayout cl = (CardLayout) (cards.getLayout());
                cl.show(cards, HomeCard);
            }
        });

        panel.add(passphraseLabel);
        panel.add(passphrase);
        panel.add(filepickerPanel);
        panel.add(decryptButton);

        cards.add(panel, DecryptCard);
    }

    private void addVerifyCard(JPanel cards) {
        JPanel panel = new JPanel(new GridLayout(0, 1));

        JLabel verifyResultLabel = new JLabel();
        verifyResultLabel.setVisible(false);

        JPanel filepickerPanel = new JPanel(new GridLayout(1, 0));
        JLabel filePathLabel = new JLabel("No file selected.");
        JButton filepickerButton = new JButton("Choose file");
        filepickerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                filePathLabel.setText(selectFile());
            }
        });
        filepickerPanel.add(filepickerButton);
        filepickerPanel.add(filePathLabel);

        JButton verifyButton = new JButton("Verify");
        verifyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String verifyResult = SignatureManagment.verifyFile(filePathLabel.getText());
                verifyResultLabel.setText(verifyResult);
                if (SignatureManagment.verificationFailure.equals(verifyResult)) {
                    verifyResultLabel.setForeground(Color.RED);
                } else {
                    verifyResultLabel.setForeground(Color.GREEN);
                }
                verifyResultLabel.setVisible(true);
            }
        });

        panel.add(verifyResultLabel);
        panel.add(filepickerPanel);
        panel.add(verifyButton);

        cards.add(panel, VerifyCard);
    }

    private void addComponents() {
        JPanel cards = new JPanel(new CardLayout());

        addHomeCard(cards);
        addCreateCard(cards);
        addImportCard(cards);
        addEncryptCard(cards);
        addDecryptCard(cards);
        addVerifyCard(cards);

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
        setBounds(300, 200, 600, 800);
        setResizable(false);
        addComponents();
        setVisible(true);
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        new Main();
    }

}
