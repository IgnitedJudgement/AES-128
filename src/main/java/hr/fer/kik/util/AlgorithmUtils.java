package hr.fer.kik.util;

import java.math.BigInteger;

/**
 * This is an utility class which provides helper methods.
 * 
 * @author Ivan Lokas
 *
 */
public class AlgorithmUtils {
	/**
	 * Number of columns (32-bit words) comprising the State. For this standard, Nb
	 * = 4
	 */
	private static final int Nb = 4;
	/**
	 * Number of 32-bit words comprising the Cipher Key. For this standard, Nk = 4
	 */
	private static final int Nk = 4;
	/**
	 * Number of rounds, which is a function of Nk and Nb (which is fixed). For this
	 * standard, Nr = 10
	 */
	private static final int Nr = 10;

	/**
	 * Retrieves the <code>roundKeyIndex</code>-th round key
	 * 
	 * @param keySchedule   provided keySchedule
	 * @param roundKeyIndex provided round key index
	 * @return <code>roundKeyIndex</code>-th round key from the given
	 *         <code>keySchedule</code>
	 */
	public static int[][] getRoundKey(int[][] keySchedule, int roundKeyIndex) {
		int result[][] = new int[Nk][Nb];

		for (int i = 0, rows = keySchedule.length; i < rows; i++) {
			for (int j = Nb * roundKeyIndex, cols = j + Nb; j < cols; j++) {
				result[i][j % Nb] = keySchedule[i][j];
			}
		}

		return result;
	}

	/**
	 * Adds a round key with the given <code>state</code>
	 * 
	 * @param state         that the round key will be added to
	 * @param keySchedule   used for round key retrieval
	 * @param roundKeyIndex used for round key retrieval
	 * @return new state with the added round key
	 */
	public static int[][] addRoundKey(int[][] state, int[][] keySchedule, int roundKeyIndex) {
		return MatrixUtils.addMatrices(state, getRoundKey(keySchedule, roundKeyIndex));
	}

	/**
	 * Adds a given <code>roundKey</code> with the given <code>state</code>
	 * 
	 * @param state    that the <code>roundKey</code> will be added to
	 * @param roundKey value that will be added to the <code>state</code>
	 * @return new <code>state</code> with the added <code>roundKey</code>
	 */
	public static int[][] addRoundKey(int[][] state, int[][] roundKey) {
		return MatrixUtils.addMatrices(state, roundKey);
	}

	/**
	 * Shifts rows in the given <code>state</code> in given <code>direction</code>.
	 * The shifting operation is in compliance with the AES standard.
	 * 
	 * @param state     of the transformation
	 * @param direction of the transformation
	 * @return new <code>state</code> with the applied shifting transformation
	 */
	public static int[][] shiftRows(int[][] state, String direction) {

		int rows = state.length;
		int cols = state[0].length;
		int result[][] = new int[rows][cols];

		for (int i = 0; i < rows; i++) {
			for (int j = 0; j < cols; j++) {
				if (direction.toUpperCase().equals("LEFT")) {
					result[i][j] = state[i][(i + j) % cols];
				} else if ((direction.toUpperCase().equals("RIGHT"))) {
					result[i][(i + j) % cols] = state[i][j];
				} else {
					throw new UnsupportedOperationException(
							String.format("Unsupported shift direction (%s)!", direction));
				}
			}
		}

		return result;
	}

	/**
	 * Mixes columns in the given <code>state</code> by multiplying it with the
	 * given <code>matrix</code>. The mixing operation is in compliance with the AES
	 * standard.
	 * 
	 * @param state  of the transformation
	 * @param matrix provided transformation template
	 * @return new <code>state</code> with the applied mixing transformation
	 */
	public static int[][] mixColumns(int[][] state, int[][] matrix) {
		int rows = state.length;
		int cols = state[0].length;
		int result[][] = new int[rows][cols];

		for (int k = 0; k < cols; k++) {
			for (int i = 0; i < rows; i++) {
				for (int j = 0; j < cols; j++) {
					result[i][k] = FiniteFieldsUtil.add(result[i][k],
							FiniteFieldsUtil.multiply(state[j][k], matrix[i][j]));
				}
			}
		}

		return result;
	}

	/**
	 * Retrieves the requested <code>colNum</code>-th column of the given
	 * <code>matrix</code>
	 * 
	 * @param matrix that contains the requested column
	 * @param colNum the index of the requested column
	 * @return the wanted column
	 */
	public static int[] getColumn(int[][] matrix, int colNum) {
		int rows = matrix.length;
		int[] result = new int[rows];

		for (int i = 0; i < rows; i++) {
			result[i] = matrix[i][colNum];
		}

		return result;
	}

	/**
	 * Inserts the given <code>column</code> in the <code>colNum</code>-th column of
	 * the given <code>matrix</code>
	 *
	 * 
	 * @param matrix that the column will be inserted into
	 * @param colNum the index of the column
	 * @param column the column that will be inserted
	 */
	public static void insertColumn(int[][] matrix, int colNum, int[] column) {
		int rows = matrix.length;

		for (int i = 0; i < rows; i++) {
			matrix[i][colNum] = column[i];
		}
	}

	/**
	 * Element-wise XOR of given words <code>a</code> & <code>b</code>
	 * 
	 * @param a first word
	 * @param b second word
	 * @return a new array which represents element-wise XOR of given words
	 */
	public static int[] xorWords(int[] a, int[] b) {
		int[] result = new int[a.length];

		for (int i = 0; i < a.length; i++) {
			result[i] = a[i] ^ b[i];
		}

		return result;
	}

	/**
	 * Returns an IV created from starting IV value in hex format, and requested
	 * increment specified by <code>index</code>
	 * 
	 * @param ivString starting IV value in hex format
	 * @param index    increment
	 * @return the requested IV
	 */
	public static int[][] createIV(String ivString, int index) {
		if (index < 0) {
			throw new IllegalArgumentException("The given index can not be negative!");
		}

		int[][] startIV = IOUtils.parseHexString(ivString, Nk, Nb, false);

		if (index != 0) {
			BigInteger ivValue = new BigInteger(ivString, 16).add(BigInteger.valueOf(index));
			String newIvString = ivValue.or(new BigInteger("100000000000000000000000000000000", 16)).toString(16)
					.substring(1);

			return IOUtils.parseHexString(newIvString, Nk, Nb, false);
		}

		return startIV;
	}

}
