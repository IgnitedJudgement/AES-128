package hr.fer.kik.util;

/**
 * This is an utility class which provides IO helper methods.
 * 
 * @author Ivan Lokas
 * 
 */
public class IOUtils {

	/**
	 * Default padding in hex format
	 */
	private static final String DEFAULT_PADDING = "00";
	/**
	 * Padding length in hex format
	 */
	private static final int PADDING_LENGTH = 2;

	/**
	 * Parses the given <code>input</code> string into a <code>int</code> matrix.
	 * The given <code>input</code> string is a string representation of
	 * concatenated hex values.
	 * 
	 * @param input which will be parsed into <code>int</code> matrix
	 * @param x     the first dimension of the resulting matrix
	 * @param y     the second dimension of the resulting matrix
	 * @param isKey boolean flag, true if parsed string is cipher key, else false
	 * @return <code>int</code> matrix populated from the given <code>input</code>
	 */
	public static int[][] parseHexString(String input, int x, int y, boolean isKey) {
		int[][] result = new int[x][y];

		for (int i = 0, length = input.length(); i < length / 2; i++) {
			int a = isKey ? i / x : i % x;
			int b = isKey ? i % (y % 4 + 4) : i / (y % 4 + 4);
			result[a][b] = Integer.parseInt(input.substring(2 * i, 2 * i + 2), 16);
		}

		return result;
	}

	/**
	 * Parses the given <code>input</code> string into a <code>int</code> matrix.
	 * The given <code>input</code> string is a string representation of
	 * concatenated hex values which can be arbitrary length, and will be padded to
	 * the size, in compliance with the specification.
	 * 
	 * 
	 * @param input which will be parsed into <code>int</code> matrix
	 * @param x     the first dimension of the resulting matrix
	 * @param y     the second dimension of the resulting matrix
	 * @param isKey boolean flag, true if parsed string is cipher key, else false
	 * @return <code>int</code> matrix populated from the given <code>input</code>,
	 *         which might have been padded
	 */
	public static int[][] parseHexStringArbitraryLength(String input, int x, int y, boolean isKey) {
		String paddedInput = padInput(input, y);
		return parseHexString(paddedInput, x, paddedInput.length() / 2 / 4, isKey);
	}

	/**
	 * Pads the given <code>input</code> in compliance to the specification.
	 * 
	 * @param input   which will be padded, if necessary
	 * @param mod     modulus of the padding
	 * @param padding the exact hex value that will be used as padding
	 * @return padded <code>input</code> matrix in compliance with the specification
	 */
	private static String padInput(String input, int mod, String padding) {
		if (padding.length() != 2) {
			throw new IllegalArgumentException("Padding length needs to be equal to 2!");
		}

		int x = 16 - input.length() / PADDING_LENGTH % 16;

		if (x % 16 == 0) {
			return input;
		}

		StringBuilder sb = new StringBuilder(input);

		for (int i = 0; i < x; i++) {
			sb.append(padding);
		}

		return sb.toString();
	}

	private static String padInput(String input, int mod) {
		return padInput(input, mod, DEFAULT_PADDING);
	}

	/**
	 * Parses the given <code>input</code> matrix into a string representation of
	 * concatenated hex values.
	 * 
	 * @param input which will be parsed into hex string representation
	 * @return the equivalent hex string representation for the given
	 *         <code>input</code> matrix
	 */
	public static String parseState(int[][] input) {
		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < input.length; i++) {
			for (int j = 0; j < input[0].length; j++) {
				sb.append(String.format("%s", Integer.toHexString(0x100 | input[j][i]).substring(1)));
			}
		}

		return sb.toString();
	}

}
