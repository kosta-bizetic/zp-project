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

import javax.crypto.KeyGenerator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Klasa {
        
        private static PGPSecretKeyRingCollection keyRingCollection = null;
        
        private static void generateRSAKeyPair(int keysize, String identity, char[] passPhrase) throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, FileNotFoundException, IOException {
            KeyPairGenerator    kpg = KeyPairGenerator.getInstance("RSA", "BC");
            
            kpg.initialize(keysize);
            
            KeyPair pair = kpg.generateKeyPair();
            
            PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
            PGPKeyPair          keyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, pair, new Date());
            PGPKeyRingGenerator    keyRingGen = new PGPKeyRingGenerator(PGPSignature.DEFAULT_CERTIFICATION, keyPair,
                    identity, sha1Calc, null, null, new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase));
            // PGPSecretKey        secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity, sha1Calc, null, null, new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase));
            
            PGPSecretKeyRing secretKeyRing = keyRingGen.generateSecretKeyRing();
            
            keyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(keyRingCollection, secretKeyRing);
            keyRingCollection.encode(new FileOutputStream("keystore"));
        }
        
        
        public static void printKeyRingCollection() {
            Iterator<PGPSecretKeyRing> iter =  keyRingCollection.getKeyRings();
            while (iter.hasNext()) {
                PGPSecretKeyRing secretKeyRing = iter.next();
                PGPSecretKey secretKey = secretKeyRing.getSecretKey();
                Iterator<String> iter2 = secretKey.getUserIDs();
                while (iter2.hasNext()) {
                    System.out.println(iter2.next());
                }
            }
        }
        
        public static void main(
            String[] args)
            throws Exception
        {
            Security.addProvider(new BouncyCastleProvider());
            
            keyRingCollection = new PGPSecretKeyRingCollection(new FileInputStream("keystore"), new BcKeyFingerprintCalculator());

            // generateRSAKeyPair(1024, "biza novi", "fraza".toCharArray());
            
            printKeyRingCollection();
            
        }
}
