package hr.fer.kik.util;

/**
 * This is an utility class which provides matrix arithmetic, for int matrices.
 * 
 * @author Ivan Lokas
 *
 */
public class MatrixUtils {

	/**
	 * Matrix multiplication
	 * 
	 * @param a the first matrix
	 * @param b the second matrix
	 * @return the product of matrices <code>a</code> and <code>b</code>
	 */
	public static int[][] addMatrices(int[][] a, int[][] b) {
		int rows = a.length;
		int cols = a[0].length;
		int[][] result = new int[rows][cols];

		for (int i = 0; i < rows; i++) {
			for (int j = 0; j < cols; j++) {
				result[i][j] = FiniteFieldsUtil.add(a[i][j], b[i][j]);
			}
		}

		return result;
	}

	/**
	 * Transposes the given matrix <code>a</code>
	 * 
	 * @param a matrix to be transposed
	 * @return transposed matrix
	 */
	public static int[][] transposeMatrix(int[][] a) {
		int rows = a.length;
		int cols = a[0].length;
		int[][] result = new int[cols][rows];

		for (int i = 0; i < rows; i++) {
			for (int j = 0; j < cols; j++) {
				result[j][i] = a[i][j];
			}
		}

		return result;
	}

	/**
	 * Method that returns the contiguous sub-array with the full height, and
	 * columns from <code>start</code>inclusive, to <code>end</code> exclusive.
	 * 
	 * @param a     matrix
	 * @param start inclusive column start index
	 * @param end   exclusive column end index
	 * @return new sub-array with the contiguous horizontal span of columns
	 *         specified by <code>start</code> & <code>end</code> indices
	 */
	public static int[][] getMatrixColumns(int[][] a, int start, int end) {
		if (start < 0 || end > a[0].length || end <= start) {
			throw new IllegalArgumentException("Invalid parameters!");
		}
		int rows = a.length;
		int[][] result = new int[rows][end - start];

		for (int i = 0; i < rows; i++) {
			for (int j = 0, length = end - start; j < length; j++) {
				result[i][j] = a[i][start + j];
			}
		}

		return result;
	}

	/**
	 * Returns a new matrix which is equal to the matrix <code>a</code> with
	 * replaced columns from given matrix <code>b</code>, starting from
	 * <code>start</code>-th index
	 * 
	 * @param a     the matrix that will be inserted into
	 * @param b     the matrix that will be inserted
	 * @param start index of starting column
	 * @return a copy of the matrix <code>a</code> which was replaced from the
	 *         <code>start</code>-th column by the matrix <code>b</code> of the same
	 *         height
	 */
	public static int[][] insertMatrixColumns(int[][] a, int[][] b, int start) {
		int rows = a.length;
		int cols = b[0].length;
		int[][] result = copyMatrix(a);

		if (start < 0 || a[0].length < start + cols) {
			throw new IllegalArgumentException("Invalid parameters!");
		}

		for (int i = 0; i < rows; i++) {
			for (int j = start; j < start + cols; j++) {
				result[i][j] = b[i][j - start];
			}
		}

		return result;
	}

	/**
	 * Method that creates a deep copy of a matrix
	 * 
	 * @param a matrix that will be copied
	 * @return deep copy of a given matrix <code>a</code>
	 */
	public static int[][] copyMatrix(int[][] a) {
		int rows = a.length;
		int cols = a[0].length;
		int[][] result = new int[rows][cols];

		for (int i = 0; i < rows; i++) {
			for (int j = 0; j < cols; j++) {
				result[i][j] = a[i][j];
			}
		}

		return result;
	}

}
