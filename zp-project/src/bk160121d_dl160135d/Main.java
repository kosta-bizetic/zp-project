package bk160121d_dl160135d;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import bk160121d_dl160135d.KeyManagement.RSA_KEYSIZE;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

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

            CryptionManagement.encryptFile("message.txt.pgp", "message.txt", pubKeys , true, PGPEncryptedData.IDEA);

            keyManagement.printSecretKeyRingCollection();
            keyManagement.close();

        }
}
