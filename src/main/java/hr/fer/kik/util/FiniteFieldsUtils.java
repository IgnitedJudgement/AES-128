package hr.fer.kik.util;

/**
 * This is an utility class which provides finite fields arithmetic, with
 * modulus 2.
 * 
 * @author Ivan Lokas
 *
 */
public class FiniteFieldsUtil {
	/**
	 * Binary mask used for retrieval of the <code>i</code>-th bit for a given byte
	 */
	public final static int[] MASK = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };

	/**
	 * Finite fields addition
	 * 
	 * @param a the first value
	 * @param b the second value
	 * @return the sum of <code>a</code> and <code>b</code>
	 */
	public static int add(int a, int b) {
		return a ^ b;
	}

	/**
	 * Finite fields addition over matrices, applied element-wise
	 * 
	 * @param a first matrix
	 * @param b second matrix
	 * @return the sum of matrix <code>a</code> and matrix <code>b</code>, applied
	 *         element-wise
	 * 
	 */
	public static int[][] add(int[][] a, int[][] b) {
		if (a.length != b.length || a[0].length != b[0].length) {
			throw new IllegalArgumentException("The dimensions of both arrays are not the same!");
		}

		int rows = a.length;
		int cols = a[0].length;
		int[][] result = new int[rows][cols];

		for (int i = 0; i < rows; i++) {
			for (int j = 0; j < cols; j++) {
				result[i][j] = add(a[i][j], b[i][j]);
			}
		}

		return result;
	}

	/**
	 * Finite fields multiplication
	 * 
	 * @param a the first value
	 * @param b the second value
	 * @return the product of <code>a</code> and <code>b</code>
	 */
	public static int multiply(int a, int b) {
		int[] tmp = new int[8];
		int result = 0;

		tmp[0] = a;

		for (int i = 1; i < tmp.length; i++) {
			tmp[i] = xtime(tmp[i - 1]);
		}

		for (int i = 0; i < tmp.length; i++) {
			if (getBit(b, i) == 0) {
				tmp[i] = 0;
			}

			result ^= tmp[i];
		}

		return result;
	}

	/**
	 * Method which returns the requested bit of a given value
	 * 
	 * @param a the value used for bit retrieval
	 * @param i the position of the wanted bit
	 * @return <code>i</code>-th bit for the given value <code>a</code>
	 */
	public static int getBit(int a, int i) {
		return (a & MASK[i]) >> i & 0x01;
	}

	/**
	 * Finite fields operation which multiplies the given value by x
	 * 
	 * @param a the value which will be multiplied by <code>x</code>
	 * @return the product of given value <code>a</code> with <code>x</code>
	 */
	public static int xtime(int a) {
		int result = (a & 0xff) << 0x01;
		return ((result & 0x100) != 0x00) ? result ^ 0x11b : result;
	}
}
