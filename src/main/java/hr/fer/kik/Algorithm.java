package hr.fer.kik;

/**
 * Interface that models a generic algorithm.
 * 
 * @author Ivan Lokas
 *
 */
public interface Algorithm {
	/**
	 * @param plaintext that will be encrypted
	 * @return ciphertext
	 */
	int[][] encrypt(int[][] plaintext);

	/**
	 * 
	 * @param ciphertext that will be decrypted
	 * @return plaintext
	 */
	int[][] decrypt(int[][] ciphertext);
}
