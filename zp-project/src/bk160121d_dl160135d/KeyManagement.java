package bk160121d_dl160135d;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
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
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

public class KeyManagement {

    public enum RSA_KEYSIZE {
        SMALL(1024), MEDIUM(2048), LARGE(4098);
        int keysize;

        RSA_KEYSIZE(int keysize) {
            this.keysize = keysize;
        }
    }

    private PGPSecretKeyRingCollection secretCollection = null;
    private PGPPublicKeyRingCollection publicCollection = null;

    private static KeyManagement instance = null;

    private KeyManagement() {
        try {
            InputStream secretKeystore = PGPUtil.getDecoderStream(new FileInputStream("secret-keystore"));
            InputStream publicKeystore = PGPUtil.getDecoderStream(new FileInputStream("public-keystore"));

            secretCollection = new PGPSecretKeyRingCollection(secretKeystore, new BcKeyFingerprintCalculator());
            publicCollection = new PGPPublicKeyRingCollection(publicKeystore, new BcKeyFingerprintCalculator());
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (PGPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public void close() {
        try {
            secretCollection.encode(new FileOutputStream("secret-keystore"));
            publicCollection.encode(new FileOutputStream("public-keystore"));
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public static KeyManagement getInstance() {
        if (KeyManagement.instance == null) {
            KeyManagement.instance = new KeyManagement();
        }
        return KeyManagement.instance;
    }

    public void generateRSAKeyPair(
            RSA_KEYSIZE keysize,
            String identity,
            char[] passPhrase)
        throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, FileNotFoundException, IOException
    {
        KeyPairGenerator    kpg = KeyPairGenerator.getInstance("RSA", "BC");

        kpg.initialize(keysize.keysize);

        KeyPair pair = kpg.generateKeyPair();

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyPair          keyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, pair, new Date());
        PGPKeyRingGenerator    keyRingGen = new PGPKeyRingGenerator(PGPSignature.DEFAULT_CERTIFICATION, keyPair,
                identity, sha1Calc, null, null,
                new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase));

        PGPSecretKeyRing secretKeyRing = keyRingGen.generateSecretKeyRing();

        secretCollection = PGPSecretKeyRingCollection.addSecretKeyRing(secretCollection, secretKeyRing);
    }

    public void printSecretKeyRingCollection() {
        Iterator<PGPSecretKeyRing> iter =  secretCollection.getKeyRings();
        while (iter.hasNext()) {
            PGPSecretKeyRing secretKeyRing = iter.next();
            PGPSecretKey secretKey = secretKeyRing.getSecretKey();
            Iterator<String> iter2 = secretKey.getUserIDs();
            while (iter2.hasNext()) {
                System.out.println(iter2.next());
            }
        }
    }

    public void exportSecretKey(PGPSecretKey key, String path) {
        try {
            FileOutputStream stream = new FileOutputStream(path);
            ArmoredOutputStream armoredStream = new ArmoredOutputStream(stream);
            key.encode(armoredStream);
            armoredStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public void exportPublicKey(PGPPublicKey key, String path) {
        try {
            FileOutputStream stream = new FileOutputStream(path);
            ArmoredOutputStream armoredStream = new ArmoredOutputStream(stream);
            key.encode(armoredStream);
            armoredStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public void importPublicKey(String path) {
        try {
            FileInputStream stream = new FileInputStream(path);
            PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(PGPUtil.getDecoderStream(stream), new BcKeyFingerprintCalculator());
            this.publicCollection = PGPPublicKeyRingCollection.addPublicKeyRing(this.publicCollection, publicKeyRing);
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    public void importSecretKey(String path) {
        try {
            FileInputStream stream = new FileInputStream(path);
            PGPSecretKeyRing secretKeyRing = new PGPSecretKeyRing(PGPUtil.getDecoderStream(stream), new BcKeyFingerprintCalculator());
            this.secretCollection = PGPSecretKeyRingCollection.addSecretKeyRing(this.secretCollection, secretKeyRing);
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (PGPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
