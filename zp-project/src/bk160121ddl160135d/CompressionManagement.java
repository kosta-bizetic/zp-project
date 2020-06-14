package bk160121ddl160135d;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;

import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPUtil;

public class CompressionManagement {

    /**
     * Compresses a file.
     *
     * @param fileName
     * Name of file to be compressed.
     * @param algorithm
     * Algorithm to be used for compression.
     * @return
     * Compressed file.
     * @throws IOException
     */
    static byte[] compressFile(String fileName, int algorithm) throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY,
            new File(fileName));
        comData.close();
        return bOut.toByteArray();
    }

}
