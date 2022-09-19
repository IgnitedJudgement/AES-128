package hr.fer.kik.util;

/**
 * This is an utility class which provides helper methods for printing.
 * 
 * @author Ivan Lokas
 *
 */
public class PrintUtils {

	/**
	 * Prints a given <code>matrix</code> in hex format
	 * 
	 * @param matrix which to be printed
	 */
	public static void printMatrix(int[][] matrix) {
		for (int i = 0, rows = matrix.length; i < rows; i++) {
			for (int j = 0, cols = matrix[0].length; j < cols; j++) {
				System.out.print(String.format("%s ", Integer.toHexString(0x100 | matrix[i][j]).substring(1)));
			}
			System.out.println();
		}
		System.out.println();
	}

	/**
	 * Prints the <code>col</code> of the given <code>matrix</code> in hex format
	 * 
	 * @param matrix that contains the requested column
	 * @param col    the requested column
	 */
	public static void printColumn(int[][] matrix, int col) {
		for (int i = 0, rows = matrix.length; i < rows; i++) {
			System.out.println(Integer.toHexString(0x100 | matrix[i][col]).substring(1));
		}
		System.out.println();
	}

	/**
	 * Prints the <code>array</code> in hex format
	 * 
	 * @param array that will be printed, as a column
	 */
	public static void printColumn(int[] array) {
		for (int i = 0, rows = array.length; i < rows; i++) {
			System.out.println(Integer.toHexString(0x100 | array[i]).substring(1));
		}
		System.out.println();
	}

}
