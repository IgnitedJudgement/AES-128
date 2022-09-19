package hr.fer.kik.demonstration;

import hr.fer.kik.AES128;
import hr.fer.kik.Cipher;
import hr.fer.kik.util.IOUtils;
import hr.fer.kik.util.PrintUtils;

/**
 * This class is used to demonstrate the functionality of a generic
 * <code>Cipher</code> implementation.
 * 
 * @author Ivan Lokas
 *
 */
public class CipherMain {

	/**
	 * The main method which is used to demonstrate the functionality of the cipher
	 */
	public static void main(String[] args) {
		//@formatter:off
		int[][] plaintext = IOUtils.parseHexStringArbitraryLength("ffeeddccbbaa9988776655443322110000112233445566778899aabbccddeeff", AES128.getNk(), AES128.getNb(), false);
		int[][] key = IOUtils.parseHexString("00102030405060708090a0b0c0d0e0f", AES128.getNk(), AES128.getNb(), true);
		//@formatter:on

		Cipher cipher = new Cipher();
		cipher.init("AES128/CTR");

		cipher.setModeOfUse(Cipher.ENCRYPT_MODE);
		int[][] ciphertext = cipher.doFinal(plaintext, key);
		cipher.setModeOfUse(Cipher.DECRYPT_MODE);
		int[][] plaintextDecrypted = cipher.doFinal(ciphertext, key);

		System.out.println("Given plaintext:");
		PrintUtils.printMatrix(plaintext);

		System.out.println("Resulting ciphertext:");
		PrintUtils.printMatrix(ciphertext);

		System.out.println("Decrypted resulting ciphertext:");
		PrintUtils.printMatrix(plaintextDecrypted);
	}

}
