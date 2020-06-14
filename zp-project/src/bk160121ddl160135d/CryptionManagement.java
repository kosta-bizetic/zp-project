package bk160121ddl160135d;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

public class CryptionManagement {

    /**
     * Decrypts a file.
     *
     * @param inputFileName
     * Name of file to be decrypted.
     * @param secRingColl
     * Secret key ring collection.
     * @param passwd
     * Passphrase for private key decryption.
     * @throws IOException
     * @throws NoSuchProviderException
     */
    public static void decryptFile(
        String                      inputFileName,
        PGPSecretKeyRingCollection  secRingColl,
        char[]                      passwd)
        throws IOException, NoSuchProviderException
    {
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        decryptFile(in, inputFileName.substring(0, inputFileName.length()-4), secRingColl, passwd);
        in.close();
    }

    private static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
            throws PGPException, NoSuchProviderException
    {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null)
        {
            return null;
        }

        return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
    }

    private static void decryptFile(
        InputStream                 in,
        String                      outputFileName,
        PGPSecretKeyRingCollection  secRingColl,
        char[]                      passwd)
        throws IOException, NoSuchProviderException
    {
        in = PGPUtil.getDecoderStream(in);

        try
        {
            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList    enc;

            Object                  o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList)
            {
                enc = (PGPEncryptedDataList)o;
            }
            else
            {
                enc = (PGPEncryptedDataList)pgpF.nextObject();
            }

            //
            // find the secret key
            //
            Iterator                    it = enc.getEncryptedDataObjects();
            PGPPrivateKey               sKey = null;
            PGPPublicKeyEncryptedData   pbe = null;

            while (sKey == null && it.hasNext())
            {
                pbe = (PGPPublicKeyEncryptedData)it.next();

                sKey = CryptionManagement.findSecretKey(secRingColl, pbe.getKeyID(), passwd);
            }

            if (sKey == null)
            {
                throw new IllegalArgumentException("secret key for message not found.");
            }

            InputStream         clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));

            JcaPGPObjectFactory    plainFact = new JcaPGPObjectFactory(clear);

            Object              message = plainFact.nextObject();

            if (message instanceof PGPCompressedData)
            {
                PGPCompressedData   cData = (PGPCompressedData)message;
                JcaPGPObjectFactory    pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

                message = pgpFact.nextObject();
            }

            if (message instanceof PGPLiteralData)
            {
                PGPLiteralData ld = (PGPLiteralData)message;

                InputStream unc = ld.getInputStream();
                OutputStream fOut = new BufferedOutputStream(new FileOutputStream(outputFileName));

                Streams.pipeAll(unc, fOut);

                fOut.close();
            }
            else if (message instanceof PGPOnePassSignatureList)
            {
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            }
            else
            {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected())
            {
                if (!pbe.verify())
                {
                    System.err.println("message failed integrity check");
                }
                else
                {
                    System.err.println("message integrity check passed");
                }
            }
            else
            {
                System.err.println("no message integrity check");
            }
        }
        catch (PGPException e)
        {
            System.err.println(e);
            if (e.getUnderlyingException() != null)
            {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    /**
     * Encrypts a file.
     *
     * @param outputFileName
     * Path to which encrypted enrcypted file will be written.
     * @param inputFileName
     * Path to the file that will be encrypted.
     * @param encKeys
     * List of public keys with which to encrypt the session key.
     * @param armor
     * Whether radix-64 conversion is required.
     * @param compression
     * Whether compression is required
     * @param encAlgorithm
     * Encryption algorithm to be used.
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws PGPException
     */
    public static void encryptFile(
        String              outputFileName,
        String              inputFileName,
        List<PGPPublicKey>  encKeys,
        boolean             armor,
        boolean             compression,
        int                 encAlgorithm)
        throws IOException, NoSuchProviderException, PGPException
    {
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));
        encryptFile(out, inputFileName, encKeys, armor, compression, encAlgorithm);
        out.close();
    }

    private static void encryptFile(
        OutputStream        out,
        String              fileName,
        List<PGPPublicKey>  encKeys,
        boolean             armor,
        boolean             compression,
        int                 encAlgorithm)
        throws IOException, NoSuchProviderException
    {
        if (armor)
        {
            out = new ArmoredOutputStream(out);
        }

        try
        {
            byte[] bytes = null;
            if (compression) {
                bytes = CompressionManagement.compressFile(fileName, CompressionAlgorithmTags.ZIP);
            } else {
                ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                PGPUtil.writeFileToLiteralData(bOut, PGPLiteralData.BINARY, new File(fileName));
                bytes = bOut.toByteArray();
            }

            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(encAlgorithm)
                    .setWithIntegrityPacket(true)
                    .setSecureRandom(new SecureRandom())
                    .setProvider("BC"));

            for(PGPPublicKey encKey : encKeys) {
                encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
            }

            OutputStream cOut = encGen.open(out, bytes.length);

            cOut.write(bytes);
            cOut.close();

            if (armor)
            {
                out.close();
            }
        }
        catch (PGPException e)
        {
            System.err.println(e);
            if (e.getUnderlyingException() != null)
            {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }
}
