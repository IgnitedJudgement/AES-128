package hr.fer.kik.demonstration;

import hr.fer.kik.AES128;
import hr.fer.kik.util.IOUtils;
import hr.fer.kik.util.PrintUtils;

/**
 * This class is used to demonstrate the functionality of the AES-128
 * implementation.
 * 
 * @author Ivan Lokas
 *
 */
public class AES128Main {

	/**
	 * The main method which is used to demonstrate the functionality of the AES-128
	 * implementation
	 */
	public static void main(String[] args) {
		AES128 aes = new AES128();
		AES128.setDebug(false);

		//@formatter:off
		int[][] plaintext = IOUtils.parseHexString("00112233445566778899aabbccddeeff", AES128.getNk(), AES128.getNb(), false);
		int[][] key = IOUtils.parseHexString("000102030405060708090a0b0c0d0e0f", AES128.getNk(), AES128.getNb(), true);
		int[][] keySchedule = aes.keyExpansion(key);
		int[][] ciphertext = aes.cipher(plaintext, keySchedule);
		int[][] plaintextDecrypted = aes.invCipher(ciphertext, keySchedule);
		//@formatter:on

		System.out.println("Given plaintext:");
		PrintUtils.printMatrix(plaintext);

		System.out.println("Resulting ciphertext:");
		PrintUtils.printMatrix(ciphertext);

		System.out.println("Decrypted resulting ciphertext:");
		PrintUtils.printMatrix(plaintextDecrypted);
	}

}
