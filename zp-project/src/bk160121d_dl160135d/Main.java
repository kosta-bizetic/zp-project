package bk160121d_dl160135d;

import java.io.FileOutputStream;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKey;

public class Main {

        public static void main(
            String[] args)
            throws Exception
        {
            Security.addProvider(new BouncyCastleProvider());

            KeyManagement keyManagement = KeyManagement.getInstance();

            List<PGPPublicKey> pubKeys = new LinkedList<PGPPublicKey>();

            pubKeys.add(keyManagement.getPublicKey(688238868389858045l));
            pubKeys.add(keyManagement.getPublicKey(6921129671440841737l));

            FileOutputStream out = new FileOutputStream("message.txt.sig");

            SignatureManagment.signFile("message.txt", 688238868389858045l, out, "stagod".toCharArray());

            CryptionManagement.encryptFile("message.txt.sig.gpg", "message.txt.sig", pubKeys , false, true, PGPEncryptedData.IDEA);

            CryptionManagement.decryptFile("message.txt.sig.gpg", keyManagement.getSecretKeyRingCollection(), "stagod".toCharArray());

            SignatureManagment.verifyFile("message.txt.sig");

//            keyManagement.printSecretKeyRingCollection();
            keyManagement.close();
        }
}
