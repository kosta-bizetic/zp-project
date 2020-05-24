package bk160121d_dl160135d;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class SignatureManagment {

    public static void verifyFile(String filePath) {
        try (InputStream in = new FileInputStream(filePath)) {
            verifyFile(in);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private static void verifyFile(InputStream in) throws Exception
    {
        in = PGPUtil.getDecoderStream(in);

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);

        // TODO: Provera da li je kompresovano
        PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();
        pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

        PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();
        PGPOnePassSignature ops = p1.get(0);

        PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();
        InputStream dIn = p2.getInputStream();

        PGPPublicKey key = KeyManagement.getInstance().getPublicKey(ops.getKeyID());

        FileOutputStream out = new FileOutputStream(p2.getFileName() + "_" + (new Date()).getTime());

        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

        int ch;
        while ((ch = dIn.read()) >= 0) {
            ops.update((byte)ch);
            out.write(ch);
        }
        out.close();

        PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

        if (ops.verify(p3.get(0))) {
            System.out.println("Signature verified.\n Signed by: " + key.getUserIDs().next());
        } else {
            System.out.println("Signature verification failed.");
        }
    }

    public static void signFile(String filePath, long keyID, OutputStream out, char[] passPhrase)
            throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {

        out = new ArmoredOutputStream(out);

        PGPSecretKey pgpSecretKey = KeyManagement.getInstance().getSecretKeyRingCollection().getSecretKey(keyID);
        PGPPrivateKey pgpPrivateKey = pgpSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passPhrase));
        PGPSignatureGenerator pgpSignatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSecretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

        pgpSignatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivateKey);

        Iterator<String> it = pgpSecretKey.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator  pgpSignatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();

            pgpSignatureSubpacketGenerator.setSignerUserID(false, it.next());
            pgpSignatureGenerator.setHashedSubpackets(pgpSignatureSubpacketGenerator.generate());
        }

        PGPCompressedDataGenerator pgpCompressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

        BCPGOutputStream bOut = new BCPGOutputStream(pgpCompressedDataGenerator.open(out));
        pgpSignatureGenerator.generateOnePassVersion(false).encode(bOut);

        File file = new File(filePath);
        PGPLiteralDataGenerator pgpLiteralDataGenerator = new PGPLiteralDataGenerator();
        OutputStream fileOutputStream = pgpLiteralDataGenerator.open(bOut, PGPLiteralData.BINARY, file);
        FileInputStream fileInputStream = new FileInputStream(file);

        int ch;
        while ((ch = fileInputStream.read()) >= 0)
        {
            fileOutputStream.write(ch);
            pgpSignatureGenerator.update((byte) ch);
        }
        pgpLiteralDataGenerator.close();
        fileInputStream.close();

        pgpSignatureGenerator.generate().encode(bOut);

        pgpCompressedDataGenerator.close();
        out.close();
    }

}
