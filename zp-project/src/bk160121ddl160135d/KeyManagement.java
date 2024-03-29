package bk160121ddl160135d;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

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

    /**
     * Size of RSA key.
     */
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

    /**
     * Writes all the keys that were created/imported during this session to file storage.
     *
     * @return
     */
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

    /**
     * Gets and instance of the KeyManagement class.
     *
     * @return
     * KeyManagement class instance.
     */
    public static KeyManagement getInstance() {
        if (KeyManagement.instance == null) {
            KeyManagement.instance = new KeyManagement();
        }
        return KeyManagement.instance;
    }

    /**
     * Generates RSA key pair.
     *
     * @param keysize
     * Size of generated RSA keys.
     * @param identity
     * Identity of RSA key owner (name surname\<email\>).
     * @param passPhrase
     * Passphrase for private key encryption.
     * @return
     * Key ID of generated key pair.
     * @throws PGPException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws FileNotFoundException
     * @throws IOException
     */
    public long generateRSAKeyPair(
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
        return secretKeyRing.getSecretKey().getKeyID();
    }

    /**
     * Delete secret key with given key ID.
     *
     * @param keyID
     * ID of the key to be deleted.
     */
    public void deleteSecretKey(long keyID) {
        try {
            secretCollection = PGPSecretKeyRingCollection.removeSecretKeyRing(secretCollection, secretCollection.getSecretKeyRing(keyID));
        } catch (PGPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    /**
     * Delete public key with given key ID.
     *
     * @param keyID
     * ID of the key to be deleted.
     */
    public void deletePublicKey(long keyID) {
        try {
            publicCollection = PGPPublicKeyRingCollection.removePublicKeyRing(publicCollection, publicCollection.getPublicKeyRing(keyID));
        } catch (PGPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    /**
     * Gets all secret keys.
     *
     * @return
     * List of userId, email and key ID for all secret keys.
     */
    public List<List<String>> getSecretKeyList() {
        List<List<String>> ret = new ArrayList<>();
        Iterator<PGPSecretKeyRing> iter =  secretCollection.getKeyRings();
        while (iter.hasNext()) {
            List<String> cur = new ArrayList<>();
            PGPSecretKeyRing secretKeyRing = iter.next();
            PGPSecretKey secretKey = secretKeyRing.getSecretKey();
            Iterator<String> iter2 = secretKey.getUserIDs();
            String userId = iter2.next();
            cur.add(userId.split("<")[0].strip());
            String email = userId.split("<")[1];
            cur.add(email.substring(0, email.length() - 1));
            cur.add(String.valueOf(secretKey.getKeyID()));
            ret.add(cur);
        }
        return ret;
    }

    /**
     * Gets all public keys.
     *
     * @return
     * List of userId, email and key ID for all public keys.
     */
    public List<List<String>> getPublicKeyList() {
        List<List<String>> ret = new ArrayList<>();
        Iterator<PGPPublicKeyRing> iter =  publicCollection.getKeyRings();
        while (iter.hasNext()) {
            List<String> cur = new ArrayList<>();
            PGPPublicKeyRing publicKeyRing = iter.next();
            PGPPublicKey publicKey = publicKeyRing.getPublicKey();
            Iterator<String> iter2 = publicKey.getUserIDs();
            String userId = iter2.next();
            cur.add(userId.split("<")[0].strip());
            String email = userId.split("<")[1];
            cur.add(email.substring(0, email.length() - 1));
            cur.add(String.valueOf(publicKey.getKeyID()));
            ret.add(cur);
        }
        return ret;
    }


//    public void printSecretKeyRingCollection() {
//        Iterator<PGPSecretKeyRing> iter =  secretCollection.getKeyRings();
//        while (iter.hasNext()) {
//            PGPSecretKeyRing secretKeyRing = iter.next();
//            PGPSecretKey secretKey = secretKeyRing.getSecretKey();
//            Iterator<String> iter2 = secretKey.getUserIDs();
//            System.out.println(secretKey.getKeyID());
//            while (iter2.hasNext()) {
//                System.out.println(iter2.next() + " " + secretKey.getKeyID());
//            }
//        }
//    }

    /**
     * Gets a public key.
     *
     * @param keyID
     * Key ID of the desired public key.
     * @return
     * Public key with the given key ID.
     */
    public PGPPublicKey getPublicKey(long keyID)
    {
        PGPPublicKey pubKey = null;
        try {
            pubKey = this.publicCollection.getPublicKey(keyID);
            if (pubKey == null) {
                PGPSecretKey secKey = this.secretCollection.getSecretKey(keyID);
                if (secKey != null) {
                    pubKey = secKey.getPublicKey();
                }
            }
        } catch (PGPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return pubKey;
    }

    /**
     * Gets the secret key collection
     *
     * @return
     * Secret key collection.
     */
    public PGPSecretKeyRingCollection getSecretKeyRingCollection()
    {
        return this.secretCollection;
    }

    /**
     * Exports a secret key.
     *
     * @param key
     * Secret key to be exported.
     * @param path
     * File path to which the key should be exported.
     */
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

    /**
     * Exports a secret key.
     *
     * @param key
     * Key ID of the secret key to be exported.
     * @param path
     * File path to which the key should be exported.
     */
    public void exportSecretKey(long keyID, String path) {
        try {
            exportSecretKey(this.secretCollection.getSecretKey(keyID), path);
        } catch (PGPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    /**
     * Exports a public key.
     *
     * @param key
     * Public key to be exported.
     * @param path
     * File path to which the key should be exported.
     */
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

    /**
     * Exports a public key.
     *
     * @param key
     * Key ID of the public key to be exported.
     * @param path
     * File path to which the key should be exported.
     */
    public void exportPublicKey(long keyID, String path) {
        exportPublicKey(getPublicKey(keyID), path);
    }

    /**
     * Imports a public key.
     *
     * @param path
     * File path from which the key should be imported.
     */
    public void importPublicKey(String path) {
        try (FileInputStream stream = new FileInputStream(path);) {
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

    /**
     * Imports a secret key.
     *
     * @param path
     * File path from which the key should be imported.
     */
    public void importSecretKey(String path) {
        try (FileInputStream stream = new FileInputStream(path)) {
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
