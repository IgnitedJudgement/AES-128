package hr.fer.kik.specification;

/**
 * The methods that are used throughout the AES standard.
 * 
 * @author Ivan Lokas
 *
 */
public interface AESMethods {

	/**
	 * Series of transformations that converts plaintext to ciphertext using the
	 * Cipher Key
	 * 
	 * @param in   the plaintext in matrix format
	 * @param word the key schedule created using the Cipher Key
	 * @return ciphertext
	 */
	int[][] cipher(int[][] in, int[][] word);

	/**
	 * Series of transformations that converts ciphertext to plaintext using the
	 * Cipher Key.
	 * 
	 * @param in   the cipertext in matrix format
	 * @param word the key schedule created using the Cipher Key
	 * @return plaintext
	 */
	int[][] invCipher(int[][] in, int[][] word);

	/**
	 * Routine used to generate a series of Round Keys from the Cipher Key
	 * 
	 * @param key used to generate the key schedule
	 * @return the key schedule for the given <code>key</code>
	 */
	int[][] keyExpansion(int[][] key);

	/**
	 * Transformation in the Cipher and Inverse Cipher in which a Round Key is added
	 * to the State using an XOR operation. The length of a Round Key equals the
	 * size of the State (i.e., for Nb = 4, the Round Key length equals 128 bits/16
	 * bytes).
	 * 
	 * @return <code>state</code> with added <code>roundKey<code>
	 */
	int[][] addRoundKey(int[][] state, int[][] roundKey);

	/**
	 * Transformation in the Cipher that processes the State using a nonlinear byte
	 * substitution table (S-box) that operates on each of the State bytes
	 * independently.
	 * 
	 * @return <code>cipher</code> after applied substitution
	 */
	int[][] subBytes(int[][] state);

	/**
	 * Transformation in the Inverse Cipher that is the inverse of SubBytes().
	 * 
	 * @return <code>state</code> after applied inverse substitution
	 */
	int[][] invSubBytes(int[][] state);

	/**
	 * @return <code>state</code> with shifted rows
	 */
	int[][] shiftRows(int[][] state);

	/**
	 * Transformation in the Inverse Cipher that is the inverse of ShiftRows().
	 * 
	 * @return <code>state</code> with inverse shifted rows
	 */
	int[][] invShiftRows(int[][] state);

	/**
	 * Transformation in the Cipher that takes all of the columns of the State and
	 * mixes their data (independently of one another) to produce new columns.
	 * 
	 * @return <code>state</code> with mixed columns
	 */
	int[][] mixColumns(int[][] state);

	/**
	 * Transformation in the Inverse Cipher that is the inverse of MixColumns()
	 * 
	 * @return <code>state</code> with inverse mixed columns
	 */
	int[][] invMixColumns(int[][] state);

	/**
	 * 
	 * Function used in the Key Expansion routine that takes a four-byte word and
	 * performs a cyclic permutation.
	 * 
	 * @return <code>word</code> after cyclic permutation
	 * 
	 */
	int[] rotWord(int[] word);

	/**
	 * 
	 * Function used in the Key Expansion routine that takes a four-byte input word
	 * and applies an S-box to each of the four bytes to produce an output word.
	 * 
	 * @return <code>word</code> after applied substitution
	 * 
	 */
	int[] subWord(int[] word);

}
