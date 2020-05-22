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
    private PGPSecretKeyRingCollection secretCollection = null;
    private PGPPublicKeyRingCollection publicCollection = null;

    private static KeyManagement instance = null;
    
    private KeyManagement() {
        InputStream secretKeystore;
        try {
            secretKeystore = PGPUtil.getDecoderStream(new FileInputStream("secret-keystore"));
            InputStream publicKeystore = PGPUtil.getDecoderStream(new FileInputStream("public-keystore"));
            
            secretCollection = new PGPSecretKeyRingCollection(secretKeystore, new BcKeyFingerprintCalculator());
            publicCollection = new PGPPublicKeyRingCollection(publicKeystore, new BcKeyFingerprintCalculator());
            
            // generateRSAKeyPair(1024, "biza <biza@mail.com>", "fraza".toCharArray());
            
            // KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
            // keyGenerator.init(168);

            secretCollection.encode(new FileOutputStream("keystore"));
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
    
    public static KeyManagement getInstance() {
        return KeyManagement.instance;
    }
    
    public void generateRSAKeyPair(
            int keysize,
            String identity,
            char[] passPhrase)
        throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, FileNotFoundException, IOException
    {
        KeyPairGenerator    kpg = KeyPairGenerator.getInstance("RSA", "BC");
        
        kpg.initialize(keysize);
        
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
    
    public void printKeyRingCollection() {
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
    
    public void exportRSAKeyPair(PGPSecretKey rsaKey) {
        try {
            FileOutputStream streamSecret = new FileOutputStream("secret.asc");
            FileOutputStream streamPublic = new FileOutputStream("public.asc");
            
            ArmoredOutputStream armoredSecret = new ArmoredOutputStream(streamSecret);
            ArmoredOutputStream armoredPublic = new ArmoredOutputStream(streamPublic);
            
            rsaKey.encode(armoredSecret);
            rsaKey.getPublicKey().encode(armoredPublic);
            
            armoredSecret.close();
            armoredPublic.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    
    public void importPublicKey() {
        try {
            FileInputStream stream = new FileInputStream("public.asc");
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
    
    public void importSecretKey() {
        try {
            FileInputStream stream = new FileInputStream("secret.asc");
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
